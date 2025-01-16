---
title: "Nosey Parker"
toc_hide: true
---
Input Type:
-
This parser takes JSON Lines Output from Nosey Parker: https://github.com/praetorian-inc/noseyparkerSupports

Supports versions [0.16.0](https://github.com/praetorian-inc/noseyparker/releases/tag/v0.16.0) and [0.22.0](https://github.com/praetorian-inc/noseyparker/releases/tag/v0.22.0) 

Things to note about the Nosey Parker Parser:
- 
- All findings are marked with a severity of 'High'
- The deduplication algorithm marks a unique finding by the secret, filepath, and line number all together
- The Nosey Parker tool allows for both full history scans of a repo and targeted branch scans
   - The Parser does NOT differentiate between the 2 scan types (may be future functionality)
  
   - **For full history scans:** 
     - The scan will pick up secrets committed in the past that have since been removed
     - If a secret is removed from source code, it will still show up in the next scan
     - When importing findings via the Dojo API, make sure to use the parameter `do_not_reactivate`  which will keep existing findings closed, without reactivating them
    - **For targeted branch scans:**
      - Keep in mind there may be active secrets that are either in the git history or not in the current branch

JSON Lines Format:
-
The parser only accepts .jsonl reports. Each line of the JSON Lines file from NoseyParker corresponds to a unique secret found with metadata for every match.


### Sample Scan Data
Sample scan data for testing purposes can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/noseyparker).