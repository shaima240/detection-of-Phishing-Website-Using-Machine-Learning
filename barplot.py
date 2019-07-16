import numpy as np
import pandas as pd
import csv
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
from collections import Counter 

df = pd.read_csv("phishcoop.csv")

# print (df)

columns = df.columns
values = df.values
res = list(df[columns[-1]])
rescount =  res.count(-1)

data = {}

for col in columns[:-1]:
    d = list(df[col])
    data.update({col:rescount/d.count(-1)})

print (data)



group_data = list(data.values())
group_names = list(data.keys())
group_mean = np.mean(group_data)

fig, ax = plt.subplots()
ax.set(title='Variable Effect')
ax.barh(group_names, group_data)
plt.show()