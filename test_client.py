import asyncio
from mcp_core.base_client import BaseClient
from attack.recon import print_recon_report
from attack.scanner import MCPScanner
from attack.exploiter import MCPExploiter


async def main():
    # Phase 2: Recon
    client = BaseClient("http://127.0.0.1:8000/mcp/")
    info = await client.connect()
    print_recon_report(info)
    
    # Phase 3: Scan
    scanner = MCPScanner(client)
    findings = await scanner.scan_all()
    
    # Phase 4: Exploit
    exploiter = MCPExploiter(client, findings)
    extracted = await exploiter.exploit_all()
    
    # Final Summary
    print("\n" + "=" * 50)
    print("FINAL SUMMARY")
    print("=" * 50)
    print(f"Vulnerabilities found: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']}")
    print(f"Data extracted: {len(extracted)} categories")

asyncio.run(main())