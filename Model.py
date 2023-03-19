import pandas as pd
import pickle
#import features_extraction
#import numpy as np

from sklearn.model_selection import train_test_split

from sklearn.tree import DecisionTreeClassifier

from sklearn import metrics



sitesData = pd.DataFrame(pd.read_csv("Database.csv"))

x = sitesData.iloc[:, :-1]
y = sitesData.iloc[:, -1]

xtrain, xtest, ytrain, ytest = train_test_split(x, y, random_state=0)
model = DecisionTreeClassifier()

model.fit(xtrain, ytrain)

ypred = model.predict(xtest)