#!/usr/bin/env python3
"""
ShadowRecon — Web Application Security Scanner
Usage:
    python main.py --web                  # Start web interface
    python main.py --url https://example.com --campaign "My Campaign"  # CLI scan
    python main.py --url https://example.com --llm           # Scan with LLM enrichment
"""

import asyncio
import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import ScanConfig
from core.engine import ScanEngine
from mapping.mapper import Mapper
from reporting.report_generator import ReportGenerator
from reporting.cvss import CVSSScorer
from exporters.training_data import TrainingDataExporter
from core.models import ScanSummary


def parse_args():
    parser = argparse.ArgumentParser(
        description="ShadowRecon — Web Application Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --web
  python main.py --url https://example.com --campaign "Pentest"
  python main.py --url https://example.com --llm --threads 50
  python main.py --url https://example.com --confirm
        """,
    )
    parser.add_argument("--web", action="store_true", help="Start web UI (FastAPI server)")
    parser.add_argument("--url", type=str, help="Target URL to scan")
    parser.add_argument("--campaign", type=str, default="default", help="Campaign name")
    parser.add_argument("--threads", type=int, default=25, help="Number of concurrent threads")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    parser.add_argument("--llm", action="store_true", help="Enable LLM enrichment (requires Ollama)")
    parser.add_argument("--confirm", action="store_true", help="Detection mode (default) or confirmation mode")
    parser.add_argument("--proxy", action="store_true", help="Enable proxy chain")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Web server host")
    parser.add_argument("--port", type=int, default=8000, help="Web server port")
    return parser.parse_args()


async def cli_scan(args):
    config = ScanConfig(
        targets=[args.url] if args.url else [],
        threads=args.threads,
        timeout=args.timeout,
        detection_mode="confirm" if args.confirm else "detect",
        proxy={"enabled": args.proxy},
        llm={"enabled": args.llm},
    )

    print(f"[*] ShadowRecon — Scanning {args.url}")
    print(f"[*] Campaign: {args.campaign}")
    print(f"[*] Threads: {args.threads} | Mode: {config.detection_mode}")
    if args.llm:
        print(f"[*] LLM enrichment: enabled ({config.llm.model_name} @ {config.llm.ollama_host})")
    print()

    engine = ScanEngine(config)
    await engine.initialize()

    campaign = await engine.create_campaign(args.campaign, f"CLI scan of {args.url}")

    def progress_callback(event, data):
        if event == "status":
            print(f"  [{data.get('status', '?')}]", end="\r")
        elif event == "finding":
            f = data
            sev = f.get("severity", "none").upper()
            print(f"  [+] [{sev}] {f.get('title', '')[:80]}")
        elif event == "scanner_done":
            print(f"  [*] Scanner '{data.get('scanner', '?')}' done: "
                  f"{data.get('findings', 0)} findings, {data.get('endpoints', 0)} endpoints")
        elif event == "complete":
            print(f"\n[*] Scan complete!")
        elif event == "error":
            print(f"\n[!] Error: {data.get('error', '?')}")

    engine.on_progress(progress_callback)

    try:
        result = await engine.run_scan(campaign.id, args.url)
    except KeyboardInterrupt:
        print("\n[!] Scan cancelled by user")
        return
    finally:
        await engine.shutdown()

    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE")
    print(f"  Target: {args.url}")
    print(f"  Duration: {result.stats.get('scan_duration_seconds', 0):.2f}s")
    print(f"  Endpoints: {result.stats.get('total_endpoints', 0)}")
    print(f"  Findings: {result.stats.get('total_findings', 0)}")
    print(f"  Critical: {result.stats.get('critical_count', 0)} | "
          f"High: {result.stats.get('high_count', 0)} | "
          f"Medium: {result.stats.get('medium_count', 0)} | "
          f"Low: {result.stats.get('low_count', 0)}")
    print(f"{'='*60}")

    summary = ScanSummary(**result.stats) if isinstance(result.stats, dict) else result.stats
    report_gen = ReportGenerator()
    paths = report_gen.generate_all(result, summary)
    print(f"\n[*] Reports saved:")
    for fmt, path in paths.items():
        print(f"    {fmt}: {path}")

    if args.llm:
        from llm.enhancer import LLMEnhancer
        enhancer = LLMEnhancer(config)
        try:
            llm_summary = await enhancer.generate_summary(result)
            if llm_summary:
                print(f"\n[*] LLM Summary:\n{llm_summary[:500]}...")
        except Exception as e:
            print(f"\n[!] LLM summary failed: {e}")

        try:
            pairs = await enhancer.generate_training_pairs(result.findings)
            if pairs:
                exporter = TrainingDataExporter()
                path = exporter.export_jsonl(pairs, result.session_id)
                print(f"[*] Training data: {path}")
        except Exception as e:
            print(f"[!] Training data export failed: {e}")

    mapper = Mapper(result.session_id)
    module_graph = mapper.process_results(result.endpoints, result.findings, result.target)
    graph_path = f"reports/graph_{result.session_id[:12]}.json"
    os.makedirs("reports", exist_ok=True)
    with open(graph_path, "w") as f:
        import json
        json.dump(module_graph.to_json(), f, indent=2)
    print(f"[*] Graph data: {graph_path}")


def main():
    args = parse_args()

    if args.web:
        print("[*] Starting ShadowRecon web interface...")
        from web.backend.api import run_server
        config = ScanConfig()
        if args.llm:
            config.llm.enabled = True
        run_server(config, host=args.host, port=args.port)
    elif args.url:
        asyncio.run(cli_scan(args))
    else:
        print("[!] Please specify --url to scan or --web to start the web interface")
        print("    Use --help for more information")


if __name__ == "__main__":
    main()
