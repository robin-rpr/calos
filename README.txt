Clearly
=======

Clearly is a lightweight (~26k LoC) container orchestrator designed for 
high-performance computing (HPC) environments.

It enables users to flexibly deploy application suites defined in a
docker-compose.yml file within specific resource allocations, while keeping
system overhead to an absolute minimum.

This allows users to define self-healing configurations for applications
deployed within long-running services, ensuring resilience without adding
unnecessary complexity.

Additionally, focus on reducing noise is particularly critical for
performance-sensitive workloads such as OSU Allreduce, where even small 
levels of interference can significantly degrade results.

Copyright 2025 (C) Clearly Systems, Inc.
