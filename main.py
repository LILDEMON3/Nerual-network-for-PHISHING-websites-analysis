from flask import Flask, render_template, request
from Model import model
from features import *
app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')


@app.route('/wordtolink', methods=['GET', 'POST'])
def link():
    link = request.form['word']
    prediction = model.predict(pandas_frame(main(link)))
    return render_template('pred.html', prediction = prediction)


@app.route('/gotomain' , methods=['GET', 'POST'])
def page1():
    react = request.form['aboutus']
    return render_template('Main.html')


if __name__ == '__main__':
  app.run(host='0.0.0.0', debug=True, port=3000)






















# import pandas as pd
# import pickle
# #import features_extraction
# #import numpy as np
#
# from sklearn.model_selection import train_test_split
#
# from sklearn.tree import DecisionTreeClassifier
#
# from sklearn import metrics
#
#
#
# sitesData = pd.DataFrame(pd.read_csv("databases/Database.csv"))
#
# x = sitesData.iloc[:, :-1]
# y = sitesData.iloc[:, -1]
#
# xtrain, xtest, ytrain, ytest = train_test_split(x, y, random_state=0)
# model = DecisionTreeClassifier()
#
# model.fit(xtrain, ytrain)
#
# ypred = model.predict(xtest)
#
# # print(metrics.classification_report(ypred, ytest))
# #
# # print("\n\nAccuracy Score:",
# #       metrics.accuracy_score(ytest, ypred).round(2) * 100, "%")
# #
# # df_test = pd.DataFrame(pd.read_csv('test.csv'))
# # print(df_test)
# # print(model.predict(df_test))