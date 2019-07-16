# Load libraries
import numpy as np  
import matplotlib.pyplot as plt  
import pandas as pd
import csv
from sklearn.metrics import classification_report, confusion_matrix,accuracy_score  
from sklearn.model_selection import train_test_split  
from sklearn.neighbors import KNeighborsClassifier  



names = ['having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol','double_slash_redirecting','Prefix_Suffix','having_Sub_Domain','SSLfinal_State','Domain_registeration_length','Favicon','HTTPS_token','Request_URL','URL_of_Anchor','Links_in_tags','SFH','Submitting_to_email','Abnormal_URL','Iframe','age_of_domain','DNSRecord','web_traffic','Google_Index','Statistical_report','Result']

print (len(names))
# Read dataset to pandas dataframe
dataset = pd.read_csv("phishcoop.csv", header=1, names=names)
dataset.head()  

print (dataset.shape)
#split dataset in features and target variable
X = dataset.iloc[:, :-1].values  
y = dataset.iloc[:, 23].values

print (X.shape)

# Split dataset into training set and test set
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20,random_state=1) 


#Create KNN classifer object
classifier = KNeighborsClassifier(n_neighbors=9)  

# Train KNN Classifer
classifier.fit(X_train, y_train)

print (X_train.shape)

#Predict the response for test dataset
y_pred = classifier.predict(X_test)
#print(y_pred,y_test)

print (X_test.shape)    


print(confusion_matrix(y_test, y_pred))  
#print(classification_report(y_test, y_pred))

#Model Accuracy, how often is the classifier correct?
print("Accuracy:",accuracy_score(y_test, y_pred))

df = pd.read_csv("output1.csv")
print (df.values[0][1:])

xvalue = np.array(df.values[0][1:]).reshape(1,-1)
print (xvalue.shape)
y1_pred= classifier.predict(xvalue)
# y1_pred= classifier.predict([[1,1,-1,1,1,-1,-1,1,-1,1,1,1,0,1,-1,1,1,1,1,-1,0,1,1]])
print(y1_pred)


"""
from sklearn.tree import DecisionTreeClassifier
model=DecisionTreeClassifier()
model.fit(X_train, y_train)

y2_pred=model.predict(xvalue)
# print("Accuracy:",accuracy_score(y_test, y2_pred))

print(y2_pred)"""



