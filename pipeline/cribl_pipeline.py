#!/usr/bin/env python3
"""Generate the Cribl cim_normalize pipeline JSON and deploy it via API.

Usage:
    python pipeline/cribl_pipeline.py [--deploy]

Without --deploy, prints the JSON to stdout.
With --deploy, creates/replaces the pipeline in Cribl Stream.
"""
import json
import sys
import urllib.request
import urllib.error

PIPELINE = {
    "id": "cim_normalize",
    "conf": {
        "functions": [
            {
                "id": "rename",
                "filter": "true",
                "description": "Save Cribl internal fields before serde overwrites them",
                "conf": {
                    "wildcardDepth": 5,
                    "renameExpr": 'C.Rename.rename(name, [[/^host$/, "_cribl_host"], [/^source$/, "_cribl_source"]])'
                }
            },
            {
                "id": "serde",
                "filter": "true",
                "description": "Parse _raw JSON into top-level ECS fields",
                "conf": {"mode": "extract", "type": "json", "srcField": "_raw"}
            },
            # --- Phase 3: Raw Sysmon text regex parsers (fallback when serde finds no JSON) ---
            {
                "id": "regex_extract",
                "filter": "!__e.event || !__e.event.code",
                "description": "Phase 3: Extract EventID from raw Sysmon text or Windows XML",
                "conf": {
                    "source": "_raw",
                    "regex": r"/EventID[=:>]\s*(?<_raw_event_code>\d+)/"
                }
            },
            {
                "id": "regex_extract",
                "filter": "_raw_event_code == '1'",
                "description": "Phase 3: Extract process fields from raw Sysmon EID 1",
                "conf": {
                    "source": "_raw",
                    "regex": r"/Image:\s*(?<_raw_image>.+?)\n[\s\S]*?CommandLine:\s*(?<_raw_cmdline>.+?)\n[\s\S]*?ParentImage:\s*(?<_raw_parent_image>.+?)\n/"
                }
            },
            {
                "id": "regex_extract",
                "filter": "_raw_event_code == '3'",
                "description": "Phase 3: Extract network fields from raw Sysmon EID 3",
                "conf": {
                    "source": "_raw",
                    # Field order in real Sysmon EID 3: Image → SourceIp → SourcePort → DestinationIp → DestinationPort
                    "regex": r"/Image:\s*(?<_raw_image>.+?)\n[\s\S]*?SourceIp:\s*(?<_raw_src_ip>[\d\.]+)[\s\S]*?DestinationIp:\s*(?<_raw_dest_ip>[\d\.]+)[\s\S]*?DestinationPort:\s*(?<_raw_dest_port>\d+)/"
                }
            },
            {
                "id": "regex_extract",
                "filter": "_raw_event_code == '7'",
                "description": "Phase 3: Extract image load fields from raw Sysmon EID 7",
                "conf": {
                    "source": "_raw",
                    "regex": r"/Image:\s*(?<_raw_image>.+?)\n[\s\S]*?ImageLoaded:\s*(?<_raw_image_loaded>.+?)\n/"
                }
            },
            {
                "id": "regex_extract",
                "filter": "_raw_event_code == '8' || _raw_event_code == '10'",
                "description": "Phase 3: Extract injection fields from raw Sysmon EID 8/10",
                "conf": {
                    "source": "_raw",
                    "regex": r"/SourceImage:\s*(?<_raw_image>.+?)\n[\s\S]*?TargetImage:\s*(?<_raw_target_image>.+?)\n/"
                }
            },
            {
                "id": "regex_extract",
                "filter": "_raw_event_code == '10'",
                "description": "Phase 3: Extract GrantedAccess from raw Sysmon EID 10",
                "conf": {
                    "source": "_raw",
                    "regex": r"/GrantedAccess:\s*(?<_raw_granted_access>0x[0-9A-Fa-f]+)/"
                }
            },
            {
                "id": "regex_extract",
                "filter": "_raw_event_code == '13'",
                "description": "Phase 3: Extract registry fields from raw Sysmon EID 13",
                "conf": {
                    "source": "_raw",
                    "regex": r"/Image:\s*(?<_raw_image>.+?)\n[\s\S]*?TargetObject:\s*(?<_raw_target_object>.+?)\n[\s\S]*?Details:\s*(?<_raw_details>.+?)\n/"
                }
            },
            {
                "id": "regex_extract",
                "filter": "_raw_event_code == '22'",
                "description": "Phase 3: Extract DNS fields from raw Sysmon EID 22",
                "conf": {
                    "source": "_raw",
                    # Field order in real Sysmon EID 22: QueryName → QueryStatus → QueryResults → Image
                    "regex": r"/QueryName:\s*(?<_raw_query_name>.+?)\n[\s\S]*?Image:\s*(?<_raw_image>.+?)\n/"
                }
            },
            # --- Phase 3: Windows Security XML field extraction (EID 4688, 4624, 7045) ---
            {
                "id": "regex_extract",
                "filter": "_raw_event_code == '4688'",
                "description": "Phase 3: Extract process fields from Windows Security EID 4688 XML",
                "conf": {
                    "source": "_raw",
                    "regex": r"/Name='NewProcessName'>(?<_raw_image>[^<]+)<[\s\S]*?Name='CommandLine'>(?<_raw_cmdline>[^<]*)<[\s\S]*?Name='ParentProcessName'>(?<_raw_parent_image>[^<]+)</"
                }
            },
            {
                "id": "regex_extract",
                "filter": "_raw_event_code == '4624'",
                "description": "Phase 3: Extract logon fields from Windows Security EID 4624 XML",
                "conf": {
                    "source": "_raw",
                    "regex": r"/Name='TargetUserName'>(?<_raw_username>[^<]+)<[\s\S]*?Name='LogonType'>(?<_raw_logon_type>[^<]+)<[\s\S]*?Name='IpAddress'>(?<_raw_src_ip>[^<]+)</"
                }
            },
            {
                "id": "regex_extract",
                "filter": "_raw_event_code == '7045'",
                "description": "Phase 3: Extract service fields from Windows Security EID 7045 XML",
                "conf": {
                    "source": "_raw",
                    "regex": r"/Name='ServiceName'>(?<_raw_service_name>[^<]+)<[\s\S]*?Name='ServiceFileName'>(?<_raw_service_file>[^<]+)</"
                }
            },
            # --- Phase 3: ECS field mapping from raw-extracted fields ---
            {
                "id": "eval",
                "filter": "_raw_event_code && !__e.event",
                "description": "Phase 3: Map raw-extracted fields to ECS dotted notation",
                "conf": {
                    "add": [
                        {"name": "event.code", "value": "_raw_event_code"},
                        {"name": "event.category", "value": "_raw_event_code == '3' ? 'network' : _raw_event_code == '7' ? 'process' : _raw_event_code == '13' ? 'registry' : 'process'"},
                        {"name": "process.executable", "value": "_raw_image || undefined"},
                        {"name": "process.name", "value": "_raw_image ? _raw_image.split('\\\\').pop() : undefined"},
                        {"name": "process.command_line", "value": "_raw_cmdline || undefined"},
                        {"name": "process.parent.executable", "value": "_raw_parent_image || undefined"},
                        {"name": "file.path", "value": "_raw_image_loaded || undefined"},
                        {"name": "file.name", "value": "_raw_image_loaded ? _raw_image_loaded.split('\\\\').pop() : undefined"},
                        {"name": "destination.ip", "value": "_raw_dest_ip || undefined"},
                        {"name": "destination.port", "value": "_raw_dest_port ? parseInt(_raw_dest_port) : undefined"},
                        {"name": "source.ip", "value": "_raw_src_ip || undefined"},
                        {"name": "registry.path", "value": "_raw_target_object || undefined"},
                        {"name": "registry.value", "value": "_raw_details || undefined"},
                        {"name": "winlog.event_data.TargetImage", "value": "_raw_target_image || undefined"},
                        {"name": "winlog.event_data.GrantedAccess", "value": "_raw_granted_access || undefined"},
                        {"name": "dns.question.name", "value": "_raw_query_name || undefined"},
                        {"name": "user.name", "value": "_raw_username || undefined"},
                        {"name": "winlog.event_data.LogonType", "value": "_raw_logon_type || undefined"},
                        {"name": "service.name", "value": "_raw_service_name || undefined"},
                        {"name": "winlog.event_data.ServiceFileName", "value": "_raw_service_file || undefined"},
                    ],
                    "remove": [
                        "_raw_event_code", "_raw_image", "_raw_cmdline",
                        "_raw_parent_image", "_raw_image_loaded", "_raw_target_image",
                        "_raw_granted_access", "_raw_target_object", "_raw_details",
                        "_raw_dest_ip", "_raw_dest_port", "_raw_src_ip", "_raw_query_name",
                        "_raw_username", "_raw_logon_type", "_raw_service_name", "_raw_service_file",
                    ]
                }
            },
            # --- CIM aliases + cleanup ---
            {
                "id": "eval",
                "filter": "true",
                "description": "Cribl processing marker + CIM aliases + cleanup",
                "conf": {
                    "add": [
                        {"name": "cribl_pipe", "value": '"cim_normalize"'},
                        {"name": "cribl_processed", "value": "true"},
                        {"name": "cribl_ts", "value": "Date.now()"},
                        {"name": "EventCode", "value": "__e.event && __e.event.code"},
                        {"name": "CommandLine", "value": "__e.process && __e.process.command_line"},
                        {"name": "Image", "value": "__e.process && __e.process.executable"},
                        {"name": "ParentImage", "value": "__e.process && __e.process.parent && __e.process.parent.executable"},
                        {"name": "TargetObject", "value": "__e.registry && __e.registry.path"},
                        {"name": "Details", "value": "__e.registry && __e.registry.value"},
                        {"name": "src_ip", "value": "__e.source && __e.source.ip"},
                        {"name": "dest_ip", "value": "__e.destination && __e.destination.ip"},
                        {"name": "dest_port", "value": "__e.destination && __e.destination.port"},
                    ],
                    "remove": ["_raw", "_cribl_host", "_cribl_source", "cribl_breaker", "source"]
                }
            }
        ]
    }
}


def deploy(cribl_url="http://localhost:9000", user="admin", password="admin"):
    """Deploy the pipeline to Cribl Stream."""
    # Authenticate
    auth_data = json.dumps({"username": user, "password": password}).encode()
    req = urllib.request.Request(
        f"{cribl_url}/api/v1/auth/login",
        data=auth_data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        token = json.loads(resp.read())["token"]

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    # Delete existing pipeline (ignore errors)
    try:
        req = urllib.request.Request(
            f"{cribl_url}/api/v1/pipelines/cim_normalize",
            method="DELETE",
            headers=headers,
        )
        urllib.request.urlopen(req, timeout=10)
        print("  Deleted existing cim_normalize pipeline")
    except urllib.error.HTTPError:
        pass

    # Create pipeline
    body = json.dumps(PIPELINE).encode()
    req = urllib.request.Request(
        f"{cribl_url}/api/v1/pipelines",
        data=body,
        method="POST",
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
            funcs = result.get("items", [{}])[0].get("conf", {}).get("functions", [])
            print(f"  Created cim_normalize pipeline with {len(funcs)} functions")
            return True
    except urllib.error.HTTPError as e:
        err = e.read().decode()[:500]
        print(f"  Failed to create pipeline: {err}", file=sys.stderr)
        return False


if __name__ == "__main__":
    if "--deploy" in sys.argv:
        url = "http://localhost:9000"
        for arg in sys.argv:
            if arg.startswith("--url="):
                url = arg.split("=", 1)[1]
        success = deploy(url)
        sys.exit(0 if success else 1)
    else:
        print(json.dumps(PIPELINE, indent=2))
