import pandas as pd
import numpy as np
import pickle 
import matplotlib.pyplot as plt
import sklearn.ensemble as ek
from sklearn import  tree, linear_model
from sklearn.feature_selection import SelectFromModel
from sklearn.externals import joblib
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn import preprocessing
from sklearn.metrics import confusion_matrix


#reading the csv file 
data = pd.read_csv('/Users/Dell/Desktop/MalwareDetClass-master/data/data.csv', sep='|', low_memory= False)



X = data.drop(['Name', 'md5', 'legitimate'], axis=1).values

y = data['legitimate'].values

#here we start creating machine learning model for our classification 



extratrees = ek.ExtraTreesClassifier().fit(X,y)
model = SelectFromModel(extratrees, prefit=True)
X_new = model.transform(X)
nbfeatures = X_new.shape[1]

#splitting csv into train and test
X_train, X_test, y_train, y_test = train_test_split(X_new, y ,test_size=0.2)


features = []
index = np.argsort(extratrees.feature_importances_)[::-1][:nbfeatures]

#listing out the features of csv file
for f in range(nbfeatures):
    print("%d. feature %s (%f)" % (f + 1, data.columns[2+index[f]], extratrees.feature_importances_[index[f]]))
    features.append(data.columns[2+f])

#here we will be using these two classifiers 
model = { "DecisionTree":tree.DecisionTreeClassifier(max_depth=10),
         "RandomForest":ek.RandomForestClassifier(n_estimators=50)}

#getting the training accuracy
results = {}
for algo in model:
    clf = model[algo]
    clf.fit(X_train,y_train)
    score = clf.score(X_test,y_test)
    print ("%s : %s " %(algo, score))
    results[algo] = score

#using the model with higher training accuracy
winner = max(results, key=results.get)

joblib.dump(model[winner], '/Users/Dell/Desktop/MalwareDetClass-master/classifier.pkl')
f=open('/Users/Dell/Desktop/MalwareDetClass-master/features.pkl', 'wb')
pickle.dump(features,f)
print('Saved')
f.close()


clf = model[winner]
res = clf.predict(X_new)
mt = confusion_matrix(y, res)
print("False positive rate : %f %%" % ((mt[0][1] / float(sum(mt[0])))*100))
print('False negative rate : %f %%' % ( (mt[1][0] / float(sum(mt[1]))*100)))

clf = model[winner]
res = clf.predict(X_test)
mt = confusion_matrix(y_test, res)



# performing test and checking the accuracy of our model
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
sc = StandardScaler()
X_train = sc.fit_transform(X_train)
X_test = sc.transform(X_test)

from sklearn.ensemble import RandomForestClassifier
classifier = RandomForestClassifier(n_estimators = 50, criterion = 'entropy', random_state = 0)
classifier.fit(X_train, y_train)

#predict the test results
y_pred = classifier.predict(X_test)

#Makeing the confusion matrix
from sklearn.metrics import confusion_matrix
cm = confusion_matrix(y_test, y_pred)
test_acc = accuracy_score(y_test,y_pred)*100
print('The test set accuracy is %4.2f%%' % test_acc)

