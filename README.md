# Evaluating ML-Based Anomaly Detection Across Datasets of Varied Quality: A Case Study

Welcome to the supporting page for the manuscript titled, _"Evaluating ML-Based Anomaly Detection Across Datasets of Varied Quality: A Case Study."_ This repository contains all the necessary files, scripts, and data analyses that complement the findings and discussions presented in the paper.

## Repository Structure

This repository is organized to facilitate easy access to the datasets, scripts, and analytical results used in our study. Below is a guide to the repository's structure:

### Folder Structure

- **[1-CICIDS-2017](1-CICIDS-2017):** This folder contains files and scripts related to the `CICIDS-2017` dataset analysis.
- **[2-WTMC-2021](2-WTMC-2021):** Here, you'll find materials associated with the `WTMC-2021` refinement of the `CICIDS-2017` dataset.
- **[3-CRiSIS-2022](3-CRiSIS-2022):** This folder includes files and scripts for the `CRiSIS-2022` refinement of the `CICIDS-2017` dataset.
- **[4-NFS-2023](4-NFS-2023):** Contains materials for our refined versions of the `CICIDS-2017` dataset, namely `NFS-2023-nTE` and `NFS-2023-TE`.
- **[visual-comparison](visual-comparison):** This section hosts Jupyter Notebooks and plots for a visual comparison of results, focusing on RF performance metrics (precision, recall, accuracy, F1 score, and AUC), confusion matrices, and feature importances.

### File Structure

Each dataset folder follows a specific naming convention for Jupyter Notebooks:
- Notebooks with `*-data-analysis*` provide a comprehensive analysis of the dataset, focusing on flow counts, label distributions, occurrences of negative and NaN values, and TCP FIN and RST flag counts.
- `*-without_feat_sel*` notebooks offer supporting material and analyses related to the manuscript.
- `*-with_feat_sel*` notebooks present extended analyses, comparing the performance of DT, RF, and NB algorithms with top 15 features selected by the ExtraTrees algorithm.

### Refined NFStream Datasets

Access our refined versions of the CICIDS-2017 dataset, generated using NFStream:

- **[NFS-2023-nTE](https://github.com/FlowFrontiers/CyberML-DataQuality/tree/main/4-NFS-2023/NFS-2023-nTE/datasets):** This dataset version does not implement TCP flag-based flow expiration, aligning with the flow generation process in existing dataset versions.
  - The code used for generating this dataset is available at [No TCP Expiry](https://github.com/FlowFrontiers/CyberML-DataQuality/blob/main/4-NFS-2023/2-NFS-2023-nTE-1-analyse-dataset.ipynb).   
- **[NFS-2023-TE](https://github.com/FlowFrontiers/CyberML-DataQuality/tree/main/4-NFS-2023/NFS-2023-TE/datasets):** This version enables TCP flag-based flow expiration, offering a dataset that closely mirrors real-world network traffic characteristics.
  - The code used for generating this dataset is available at [TCP Expiry](https://github.com/FlowFrontiers/CyberML-DataQuality/blob/main/4-NFS-2023/3-NFS-2023-TE-1-analyse-dataset.ipynb).

## Documentation

To gain a comprehensive understanding of the methodologies and insights underlying this project, we encourage you to refer to our detailed research paper associated with this repository. The paper delves into the nuances of the data preparation process, the analytical methods employed, and the broader implications of our findings in the field of network anomaly detection. It serves as an essential resource for those looking to explore the depths of machine learning applications in cybersecurity.

For further insights and an in-depth exploration of our methodologies, the research paper provides a rich source of information and context, enhancing the practical and theoretical understanding of the work presented in this repository.

---
