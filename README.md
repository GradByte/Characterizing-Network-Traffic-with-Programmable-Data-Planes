# Traffic Characterization and P4 Comparison

This Google Colab notebook performs an in-depth analysis of network traffic, focusing on statistical characterization and a comparative study between software-based (Python/Scapy) and hardware-assisted (P4) feature extraction methods.

## Table of Contents
1.  [Overview](#overview)
2.  [Task I: Software-based Traffic Characterization and Statistical Analysis](#task-i-software-based-traffic-characterization-and-statistical-analysis)
3.  [Task II & III: In-Network Feature Extraction using P4 & Comparison](#task-ii--iii-in-network-feature-extraction-using-p4--comparison)
4.  [Conclusion](#conclusion)

## Overview
This notebook analyzes a `.pcap` network trace to extract various traffic features such as packet size, inter-arrival time (IAT), and flow-level statistics. It then performs statistical modeling on these features to find the best-fit distributions. Finally, it compares the results obtained from traditional software-based analysis with those from P4-based in-network feature extraction.

## Task I: Software-based Traffic Characterization and Statistical Analysis
This section utilizes `Scapy` to parse a `.pcap` file and `pandas` to process the extracted packet data. Key analyses include:

-   **Packet Feature Extraction**: Capturing timestamp, size, inter-arrival time (IAT), protocol, source/destination IP, and ports.
-   **Distribution Fitting**: Statistical distributions (Exponential, Log-Normal, Weibull, Pareto, Gamma) are fitted to the IAT data. The Pareto distribution was identified as the **best fit** based on AIC values.
-   **Sample Size Impact**: An investigation into how sample size affects the goodness-of-fit tests (KS-statistic and P-value), demonstrating the variability with small samples versus the stability with larger datasets.
-   **Protocol-wise Analysis**: Comparing packet size and IAT distributions for TCP and UDP protocols.
-   **Flow Analysis**: Classification of network flows into 'short' and 'long' flows based on packet count, and a comparison of their aggregated statistics (packet count, byte count, average packet size, duration).

**Key Findings from Task I:**
-   The IAT data exhibits high skewness, making accurate distribution fitting challenging, especially with small sample sizes.
-   The Pareto distribution provided the best fit for the observed IAT data.
-   Small sample sizes can lead to misleading P-values in statistical tests.
-   Significant differences exist between short and long flows in terms of average packet count, byte count, and duration.

## Task II & III: In-Network Feature Extraction using P4 & Comparison
This section loads pre-computed flow statistics and IAT samples obtained from a P4-enabled switch (simulated or real). It then performs a direct comparison with the software-based results from Task I.

-   **Metric Comparison**: Bar charts are used to visualize and compare total packets, average packet size, and active flows between Task I (Python) and Task II (P4).
-   **Flow-level Distribution Comparison**: Histograms compare the distributions of packets per flow and average packet size per flow between the two methods.
-   **IAT Comparison**: A detailed statistical comparison of IAT (mean, median, min, max, std) is performed, along with distribution plots (linear and log scale), highlighting differences and similarities.

**Key Findings from Task II & III:**
-   The P4-based method accurately captures total packet counts and average packet sizes, with minimal percentage differences compared to the Python ground truth.
-   Differences in active flow counts suggest potential discrepancies in flow definition or aggregation mechanisms between the two approaches.
-   While the mean and standard deviation of IAT are very close, the median, min, and max IAT values show more significant percentage differences, indicating potential granularity or precision differences in hardware-based timestamping or processing.
-   The overall shape of the IAT distributions (especially on a log scale) remains similar between Python and P4, despite some quantitative differences.

## Conclusion
This notebook demonstrates the capabilities of both software-based and P4-based methods for network traffic analysis. While software tools like Scapy and Pandas offer high precision and flexibility for detailed analysis, P4-enabled devices can provide highly efficient, real-time in-network feature extraction. The comparison highlights areas of strong agreement and points out where differences might arise due to measurement methodologies or hardware limitations.
