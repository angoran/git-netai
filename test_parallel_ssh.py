#!/usr/bin/env python3
"""
Test script to compare sequential vs parallel SSH execution performance.
"""

import asyncio
import time
from connectors.ssh_c import send_custom_command, send_custom_command_parallel


async def test_sequential():
    """Test sequential execution on 4 routers."""
    routers = [
        "10.140.3.19",
        "10.140.3.20",
        "10.140.3.57",
        "10.140.3.58"
    ]
    command = "show version"

    print("=" * 60)
    print("SEQUENTIAL EXECUTION TEST")
    print("=" * 60)

    start_time = time.time()

    results = {}
    for ip in routers:
        print(f"Connecting to {ip}...")
        result = await send_custom_command(ip, command)
        results[ip] = result
        print(f"  -> {ip}: {'SUCCESS' if result['success'] else 'FAILED'}")

    end_time = time.time()
    elapsed = end_time - start_time

    print(f"\nTotal execution time: {elapsed:.2f} seconds")
    print(f"Average per router: {elapsed/len(routers):.2f} seconds")

    return elapsed, results


async def test_parallel():
    """Test parallel execution on 4 routers."""
    targets = [
        {"ip": "10.140.3.19", "command": "show version"},
        {"ip": "10.140.3.20", "command": "show version"},
        {"ip": "10.140.3.57", "command": "show version"},
        {"ip": "10.140.3.58", "command": "show version"}
    ]

    print("\n" + "=" * 60)
    print("PARALLEL EXECUTION TEST")
    print("=" * 60)

    start_time = time.time()

    results = await send_custom_command_parallel(targets, timeout=60)

    end_time = time.time()
    elapsed = end_time - start_time

    print(f"Executed {len(targets)} commands in parallel")
    for ip, result in results.items():
        print(f"  -> {ip}: {'SUCCESS' if result.get('success') else 'FAILED'}")

    print(f"\nTotal execution time: {elapsed:.2f} seconds")

    return elapsed, results


async def main():
    """Run both tests and compare results."""
    print("Starting SSH execution comparison test...")
    print("Target routers: 10.140.3.19, 10.140.3.20, 10.140.3.57, 10.140.3.58")
    print("Command: show version\n")

    # Test sequential
    seq_time, seq_results = await test_sequential()

    # Wait a bit between tests
    await asyncio.sleep(2)

    # Test parallel
    par_time, par_results = await test_parallel()

    # Compare results
    print("\n" + "=" * 60)
    print("PERFORMANCE COMPARISON")
    print("=" * 60)
    print(f"Sequential execution: {seq_time:.2f} seconds")
    print(f"Parallel execution:   {par_time:.2f} seconds")
    print(f"Time saved:           {seq_time - par_time:.2f} seconds")
    print(f"Speed improvement:    {seq_time / par_time:.2f}x faster")
    print(f"Efficiency gain:      {((seq_time - par_time) / seq_time * 100):.1f}%")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
