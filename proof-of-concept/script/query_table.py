from fair_tables import *
from constants import  *

def save_table_to_db(fair_tb: FAIRTable, filename, table_name):
    try:
        with open(filename, "r") as file:
            data = json.load(file)
    except (FileNotFoundError,json.decoder.JSONDecodeError):
        data = {}
    data[table_name] = {
        "x": fair_tb.x.value,
        "y": fair_tb.y.value,
        "table": fair_tb.table.tolist()
    }

    with open(filename, "w") as file:
        json.dump(data, file)


def query_table():
    table_name = input("Enter the parent metric for the table:").upper()
    if all([table_name != m.value.upper() for m in Metric]):
        print("The name of the table must be a metric")
        return
    table_name = metric_reverse_dict[table_name].value

    x = input("Enter the x-axis metric for the table:").upper()
    if all([x != m.value.upper() for m in Metric]):
        print("The x-axis must be a metric")
        return
    y = input("Enter the y-axis metric for the table:").upper()
    if all([y != m.value.upper() for m in Metric]):
        print("The y-axis must be a metric")
        return

    arr = []

    for i in range(SCALE):
        row = input(
            f"Enter comma-separated values for {y}={state_to_semantic[SCALE - i - 1]} and {x} over [VL,L,M,H,VH]:").split(
            ",")
        row = [acronym_dict[j.upper()] for j in row]
        if len(row) != SCALE:
            print(f"The row should contain {SCALE} values.")
            return
        arr.append([semantic_to_state[j] for j in row])
    x = metric_reverse_dict[x]
    y = metric_reverse_dict[y]
    save_table_to_db(FAIRTable(np.array(arr), x, y), FAIR_DB_NAME, table_name)

query_table()


