# Finding Similar Code Vulnerabilities to Propose Code Patches

This repository includes
 - Acquiring taint flow steps from SonarCloud based on [toolbox](https://github.com/eric-therond-sonarsource/toolbox/tree/master/sonarcloud) output
 - Pre-processing the taint flow steps by filtering irrelevant information
 - Extracting additional features
 - Acquiring taint flow steps of fixed vulnerabilities from SonarCloud and identifying the patch commit from GitHub
 - Labels for a set of vulnerabilities that are considered similar
 - Jupyter notebooks that implement different language models and evaluate their capabilities to capture similarity criteria

## Scripts
The scripts are only tested for Java code.

`taints.py`
 - info: Receives the taint flow steps from SonarCloud based on id
 - input: `issues.json` (toolbox data)
 - output: `java_taints.json`
   - `id, [taint flow step, file]`

`clear.py`
 - info:
   - can fix some syntax therefore AST can be built
   - may remove
     - consecutively executed function calls and definitions
     - method declarations in general
     - method annotations
 - input: `java_taints.json`
   - `id, [taint flow step, file]`
 - output: `java_taints_cleaned.json`
   - `id, [taints flow steps, file], cleard [taint flow steps, file]`

`features.py` (not used for the current prototype state)
 - info:
   - can extract and replace strings and variables in taint flow
   - can look for similarity criteria
 - input: `java_taints.json` / `java_taints_cleaned.json`
   - `[taint flow step, file]`
 - output: `java_taints_features.json`
   - `id, [taint flow step, file], features: {strings, variables, cleaned}`

`patch_api_calls.py`
 - info: 
   - iterates through SonarCloud orgs to query fixed Java SQLi or XSS issues
   - identifies the patch commit based on issue `updateDate`
   - gets the taint locations from GitHub and applies taint locations
   - needs github token to not reach api limit
   - taint flow can be cleared using `clear.py`
 - input: change `get_orgs(1, 100, 500)` *(startpage, endpage, pagesize)* to read more orgs
 - output: `patched_taints.json`
   - `id, [taint flow step, file], vulnHash, patchHash, rule, owner, repo`

## Notebooks
The notebooks `CuBERT.ipynb`, `CodeBERT.ipynb`, `code2vec_token.ipynb`, and `code2vec_predict_vector.ipynb` need the labels in `label_java_<type>.json` to evaluate as well as some taint flows to calculate the embeddings, e.g., `java_taints_cleaned.json` to embed the clean taint flow steps.

`Prototype.ipynb` first embeds all issues from `java_taints_cleaned.json` (test set) and `java_taints_patched.json` (patch set). Then one issue from the test set can be queried to get the patch set issue ordered by similarity. The patches are proposed through printing the "target" by linking the GitHub diff.

It is recommended to load the notebooks and data into Google Colab to use their free GPU power. Otherwise it takes significantly longer (~7 minutes for prototype) to calculate the embeddings on CPU.

## Labels
The `label_java_<type>.json` files consist of arrays with SonarCloud issue ids while each array represents a similarity criteria. For details please have a look at the thesis.
