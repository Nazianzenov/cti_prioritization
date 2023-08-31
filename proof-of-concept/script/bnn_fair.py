"""Module implementing the basic function related ot the Bayesian FAIR model"""
from sklearn.linear_model import LinearRegression
from fair_tables import FAIRTable, Metric,TABLES_DICT
from constants import SCALE, scale_table, K

LEF_table = TABLES_DICT[Metric.LEF]

CA_table = TABLES_DICT[Metric.TEF]

TC_table = TABLES_DICT[Metric.V]


# indexing methods
def get_row_vector(table, code: int):
    """
    tool method for returning a row from the table
    :param table: FAIR table
    :param code: state of the y-axis
    :return: state vector
    """
    return table[SCALE - code - 1]


def get_col_vector(table, code):
    """
       tool method for returning a column from the table
       :param table: FAIR table
       :param code: state of the x-axis
       :return: state vector
       """
    return [row[code] for row in table]


def get_elem(table, metric_x, metric_y):
    """
    tool method for returning an element from the table
    :param table: FAIR table
    :param metric_x: state value of x
    :param metric_y: state value of y
    :return: state value at coordinates x,y
    """
    return table[SCALE - metric_x - 1][metric_y]


# weight vectors computation
def get_weight_vector(table):
    """
    computes the weights of the table's metrics using linear regression
    :param table: FAIR table
    :return: weights of the table metrics
    """

    # Flatten the data into separate lists
    flatten_scale_pair = [[scale_table[i], scale_table[j]]
                          for i in range(SCALE) for j in range(SCALE)]
    flatten_scale = [table[i][j] for i in range(SCALE) for j in range(SCALE)]

    # Create and train the linear regression model
    model = LinearRegression()
    model.fit(flatten_scale_pair, flatten_scale)

    # Get the coefficients
    coeff_a = model.coef_[0]
    coeff_b = model.coef_[1]

    alpha = abs(coeff_a) / (abs(coeff_a) + abs(coeff_b))
    beta = abs(coeff_b) / (abs(coeff_a) + abs(coeff_b))
    return alpha, beta


def compute_fuzzy_elem(table: FAIRTable, code: int, metric: Metric):
    """
    method computing the value of an element in a judging vector
    :param table: FAIR table
    :param code: state value of the element
    :param metric: metric type
    :return: the numerator of the judging value for the given element
    """
    if metric.value == table.x.value:
        vector = get_col_vector(table.table, code)
    else:
        vector = get_row_vector(table.table, code)
    numerator = code * sum(pow(K, state) for state in vector)
    return numerator


def compute_fuzzy_vector(table, metric: Metric):
    """
    computes the judging vector of a given metric
    :param table: FAIR table
    :param metric: metric type of the vector
    :return: the related fuzzy judging vector
    """
    if metric.value not in (table.x.value, table.y.value):
        return None
    denominator = 0
    if metric.value == table.x.value:
        for i in range(0, SCALE):
            denominator += scale_table[i] * \
                           sum(pow(K, table.table[j][i]) for j in range(0, SCALE))
    else:
        for i in range(0, SCALE):
            denominator += scale_table[i] * \
                           sum(pow(K, table.table[SCALE - i - 1][j]) for j in range(0, SCALE))
    fuzzy_vector = []
    for i in scale_table:
        fuzzy_vector.append(compute_fuzzy_elem(table, i, metric) / denominator)
    return fuzzy_vector


# CPT computation
def sig(difference, second_factor):
    """
    mathematical tool used for computing conditional probability
    tables
    :param difference: first_factor - second-factor
    :param second_factor: 2nd factor in the difference
    """
    return difference if difference >= 0 else second_factor


def compute_cpt(f_vectors, weights, s_e, s_c):
    """
    method computing a conditional probability table
    :param f_vectors: fuzzy judging vectors of a metric
    :param weights: weights related to the metric
    :param s_e: state of the effect (metric)
    :param s_c: state of the causes (sub-metrics)
    :return: the conditional probability P(e=j|c1=j1, ..., cn = jn)
    """
    return sum(weights[l] * f_vectors[l][sig((s_c[l] - s_e), s_e)] for l in range(len(weights)))


def compute_score(res):
    """
    Given the result of bayesian inference, computes a unique score
    :param res: bayesian inference result (vector of probabilities)
    :return: a weighted score
    """
    weights = [1, 2, 4, 8, 16]  # to be potentially changed
    return sum(r * s for r, s in zip(res, weights))
