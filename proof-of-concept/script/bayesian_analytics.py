import random
import numpy as np
from bnn_fair import Metric,compute_score
from FAIR_tree import BFModel,StateDictionary
import matplotlib.pyplot as plt
from scipy.stats import percentileofscore

nb_samples = 50000
MAX = 4
MIN = 0

INTERVALS = [
    (0, 20, "Very Low Relevance"),
    (20, 40, "Low Relevance"),
    (40, 60, "Moderate Relevance"),
    (60, 80, "High Relevance"),
    (80, 100, "Very High Relevance")
]
def bayesian_score(s):
    state_d = {
        Metric.IS.value: s,
        Metric.SM.value: s,
        Metric.GS.value: s,
        Metric.OM.value: s,
        Metric.LSC.value:s,
        Metric.LSA.value:s,
        Metric.SL.value: s,
        Metric.R.value: s,
        Metric.AC.value: s,
        Metric.EX.value: s,
        Metric.CES.value: 4-s,
    }

    b = BFModel(StateDictionary(state_d,True))
    b.compute_BN()
    l = b.compute_LEF_inference()
    print(l)
    print(compute_score(l))


def get_bayesian_score_graph():
    values = []
    counter = 0
    for i in range(nb_samples):
        if 100*counter / nb_samples in list(np.arange(0,101,1)):
            print(f"{100*counter/nb_samples}% COMPLETED")
        counter+=1
        state_di = {
    Metric.IS.value: random.randint(0,4),
    Metric.SM.value: random.randint(0, 4),
    Metric.GS.value: random.randint(0, 4),
    Metric.OM.value: random.randint(0, 4),
    Metric.LSC.value: random.randint(0, 4),
    Metric.LSA.value: random.randint(0, 4),
    Metric.SL.value: random.randint(0, 4),
    Metric.R.value: random.randint(0, 4),
    Metric.AC.value: random.randint(0, 4),
    Metric.EX.value: random.randint(0, 4),
    Metric.CES.value: 4 - random.randint(0, 4),
    }

        b = BFModel(StateDictionary(state_di, True))
        b.compute_BN()
        l = b.compute_LEF_inference()
        values.append(compute_score(l))
    return sorted(values)

def generate_data():
    # Sample array of floats
    data = get_bayesian_score_graph()

    np.savetxt("data.txt", data, fmt="%.4f")

    # Creating the histogram
    plt.hist(data, bins=20, edgecolor='black')  # You can adjust the number of bins

    # Adding labels and title
    plt.xlabel('Value')
    plt.ylabel('Frequency')
    plt.title('Distribution of Bayesian FAIR Outputs')

    plt.savefig('bayesian_distrib.png')

    # Display the plot
    plt.show()

generate_data()

def get_data():
    with open("data.txt", "r") as d:
        data = np.array([float(line.strip()) for line in d])
    return data
def process_data():

    data = get_data()
    # Creating the histogram
    plt.hist(data, bins=20, edgecolor='black')  # You can adjust the number of bins

    # Adding labels and title
    plt.xlabel('Value')
    plt.ylabel('Frequency')
    plt.title('Distribution of Bayesian FAIR Outputs')
    plt.show()

        # making the data uniform:
    percentile_ranks = [percentileofscore(data, value) for value in data]
    sorted_data_with_ranks = sorted(zip(data, percentile_ranks), key=lambda x: x[0])

    # Sort the data and percentile ranks
    sorted_data = np.sort(data)
    sorted_percentile_ranks = np.sort(percentile_ranks)

    # Create a plot of data values against percentile ranks
    plt.plot(sorted_data, sorted_percentile_ranks, marker='o')

    # Adding labels and title
    plt.xlabel('Sorted Data Values')
    plt.ylabel('Sorted Percentile Ranks')
    plt.title('Transformation of Data Distribution')

    plt.savefig('percentile.png')
    # Display the plot
    plt.show()
    return percentile_ranks

from scipy.stats import uniform
def show_data_is_uniform(percentile_ranks):
    # Step 1: Sort the percentile ranks
    sorted_percentile_ranks = np.sort(percentile_ranks)

    # Step 2: Generate values from a uniform distribution between 0 and 1
    num_values = len(sorted_percentile_ranks)
    uniform_values = np.random.random(num_values)

    # Step 3: Use the inverse CDF of a uniform distribution to map to uniform values
    uniform_distribution = uniform(loc=0, scale=1)  # Uniform distribution [0, 1]
    uniform_mapped_values = uniform_distribution.ppf(uniform_values)

    # Create a histogram of the mapped values
    plt.hist(uniform_mapped_values, bins=20, edgecolor='black', alpha=0.7, label='Approx. Uniform Distribution')

    # Adding labels and legend
    plt.xlabel('Mapped Uniform Values')
    plt.ylabel('Frequency')
    plt.title('Approximation of Uniform Distribution using Percentile Ranks')
    plt.legend()

    plt.savefig('approx_uniform.png')
    # Display the plot
    plt.show()

show_data_is_uniform(process_data())


def rank_score(sc):
    percentile_rank = percentileofscore(get_data(), sc)
    for start, stop, label in INTERVALS:
        if start <= percentile_rank < stop:
            return label