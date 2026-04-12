1. Current Demo Identification:
Please isolate and identify it descriptively based on the software pair and the attack vector. Let's name the environment folder ats_gevent and the specific testcase "Trailer Section Injection".

2. Future Demo Examples:
We plan to add both different attack types and different proxy/backend pairs. For example:

Demo 2: nginx_gunicorn (Nginx < 1.17.x + Gunicorn ~20.0.x) demonstrating classic TE.CL or CL.TE vulnerabilities.

Demo 3: haproxy_nodejs demonstrating obfuscated TE headers.

3. Shared vs Demo-Specific Code:

Shared: The entire testing engine should be shared and reusable. This includes attacker/main.py, sender.py, and utils.py. The tester script should accept a --target argument to know which pair to test.

Demo-Specific: * Each proxy/backend pair must have its own isolated folder containing its specific docker-compose.yml, proxy/ configs, and backend/ code.

Each attack type will have its own testcase script (e.g., tc_01_trailer_injection.py, tc_02_te_cl.py) and its own raw payload file (.txt) stored in the shared tester/ directory but called specifically based on the scenario.

4. Desired Structure:
Yes, I already have a strict, modular folder structure designed for this exact purpose. Please use the following layout:

Plaintext
http-desync-lab/
│
├── pairs/                              <-- Demo-specific environments
│   ├── ats_gevent/                     <-- Demo 1
│   │   ├── docker-compose.yml
│   │   ├── proxy/                      (Dockerfile, remap.config, records.config)
│   │   └── backend/                    (Dockerfile, app.py, requirements.txt)
│   │
│   └── nginx_gunicorn/                 <-- Demo 2 (Future)
│       └── ...
│
├── tester/                             <-- Shared testing engine
│   ├── payloads/                       (e.g., trailer_smuggle.txt, te_cl.txt)
│   ├── run_test.py                     (Entry point alias)
│   └── requirements.txt
│
├── attacker/                           <-- Core logic modules
│   ├── main.py
│   ├── sender.py
│   ├── utils.py
│   └── testcases/                      (tc_01_trailer_injection.py, etc.)
│
└── output/                             <-- Auto-generated results
    ├── ats_gevent/
    │   ├── raw_traffic.log
    │   └── report.json
    └── nginx_gunicorn/
Please proceed with reorganizing the codebase to strictly match this structure.