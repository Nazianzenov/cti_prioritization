# Risk-based CTI prioritization in operational context


<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/github_username/repo_name">
    <img src="resources/rhea_logo.png" alt="Logo" width="400" height="300">
  </a>

<h3 align="Risk-based CTI prioritization in operational context</h3>

  <p align="center">
    Repository containing the Proof Of Concept for the theoretical framework designed as part of my summer internship
    at RHEA Group in 2023.
    <br />>
    <a href="https://github.com/Nazianzenov/cti_prioritization/issues">Report Bug</a>
    ·
    <a href="https://github.com/Nazianzenov/cti_prioritization/issues">Request Feature</a>
  </p>
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
  </ol>
</details>


### Prerequisites

The following tools are used in the framework
* python3
* neo4j desktop

The following python libraries are required for running the framework:
* pgmpy
* numpy
* sklearn
* neo4j
* stix2
* difflib

### Command line interface

1. Clustering
    ```sh
     python3 main.py cluster
   ```
2. Scoring
   ```sh
    python3 main.py score
   ```

Parameters in the main.py file:
* stix bundle url

<p align="right">(<a href="#readme-top">back to top</a>)</p>
