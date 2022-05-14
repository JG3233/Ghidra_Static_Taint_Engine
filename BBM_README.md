# Basic Block Model Ghidra Engine

## Background 

The BBM script was a MS Project by Jacob Gilhaus on using Ghidra as a taint analysis engine. The primary file is `ref2sink_bbm.py` and it factors in buffer overflows, command injection, control-flow (with some early update related enhancements), and basic IPC communication. Ben Gilman is working on the complementary script for the IPC portion, so this engine simply reads from the output file that script will produce. An example can be seen under `search_results/shared.example`.

This engine offers more Ghidra tools than counterparts such as SaTC, and by using the Basic Block Model it can perform comparable tasks nearly 10x as fast. For more information, refer to the MS paper: `Static_Taint_Analysis_with_Ghidra_v1.1.pdf`.

The Ghidra API documentation is used heavily and provides far more functionality than I was able to take advantage of here: [Ghidra API](https://ghidra.re/ghidra_docs/api/index.html)

## Running

There are two possible ways to run the Ghidra scripts, one more general and one better fit for testing on individual binaries. To run generally, we can just use the regular main.py file on an extracted firmware image. Of course, we need to update taint_config.py to select for ref2sink_bbm as one of the scripts we would like to run.

### Generally

```
python3 main.py [unpacked_firmware_filesystem_path]
```

### Testing

For testing purposes, some manual alterations are necessary. First, we need to adjust the ghidra_analysis.py import path for taint_config by removing 'ghidra_analyzer.' since we will be running ghidra_analysis directly. For example, on line 3 use:
```
from taint_config import GHIDRA_SCRIPTS, SCRIPTS_PATH, GHIDRA_RESULTS, HEADLESS_GHIDRA, SEARCH_RESULTS, ANGR_RESULTS
```
instead of:
```
from ghidra_analyzer.taint_config import GHIDRA_SCRIPTS, SCRIPTS_PATH, GHIDRA_RESULTS, HEADLESS_GHIDRA, SEARCH_RESULTS, ANGR_RESULTS
```

Then, we also need to adjust where the script reads from. A successful work flow seems to be at least two terminals, one for running the main script and another for editing the necessary files between runs.

Edit binaries.txt in the search_results directory to include only the examples you would like to test, i.e `./bbm_tester_files/tester`. Then, continue one directory deeper into search_results/elf_info and verify that the test binary (tester in this example) has a corresponding entry in elf_info. This file contains the keywords that we would like to search for buffer overflows and command injection. For reference, if you cat out tester you should see the string "Welcome!".

Finally, run the script:
```
python3 ghidra_analyzer/ghidra_analysis.py
```

### Script Functionality

The functionality of ref2sink_bbm.py can be described as follows. First, if run with main.py, the binaries.txt file is populated along with the keyword information in elf_info. Then, main refers to ghidra_analysis to run the desired Ghidra scripts. Supposing `ref2sink_bbm` is included in taint_config, only then will the script be invoked.

On invocation, the script reads in the keyword file argument into paramTargets and opens a file for writing the results. Then the shared IPC file is checked before proceeding into performing buffer overflow, command injection, and control-flow analysis. A VULNS_TO_CHECK list is provided if we do not wish to check for all vulnerabilities. 

Once a vulnerability is being checked, each paramTarget is enumerated and searched with findSinkPath as well as any IPC checks for bufO and cmdI. For buffer overflow and command injection, the kw_search function is used. Control-flow has addtional functionality so it uses the cf_search function. findSinkPath helps determine the starting location of the search script before calling the right search.

For keywords, each keyword location will be searched until a path is found, while control-flow attempts to start at main, gathering the full program control-flow.

The search functions use the Basic Block Model to perform a DFS, keeping track of the path and past visited blocks. Sinks are identified by checking the block label against a list of potential sink functions for this vulnerability.

cf_search also attempts to verify any cryptographic functions along paths to a sink function using the symbol table. Some logic is also left that attempts to retrieve calling arguments to vulnerable functions, though the author did have some difficulties with this crashing the script on my system. 

The scripts are commented to the best of my ability to also explain the functionality in more detail, as well as including DEBUG, VERBOSE, VVERBOSE, and debugging functions that print various pieces of information. While much SaTC functionality has been pruned in favor of this new engine, some functions that may prove useful in the future are also left.


**Author: Jacob Gilhaus**