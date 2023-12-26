import warnings
import nltk
nltk.download('punkt')
import gensim
from gensim.models.doc2vec import Doc2Vec, TaggedDocument
from nltk.tokenize import word_tokenize
from numpy import *
from urllib.parse import unquote

import numpy as np
import pandas as pd
import csv
import urllib.parse as parse
import pickle


testXSS = []
testNORM = []
X_temp = []
X = []
y = []
xssnum = 0
notxssnum = 0

print("Gathering Data...")
# gather the XSS string and append the label of 1 to y array

#------------------------------------------------------------------
# CSV dosyasını oku
df = pd.read_csv('XSS_dataset.csv')

# XSS verilerini 'xss.txt' dosyasına yazma
with open('testXSS.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(df['Sentence'][df['Label'] == 1]))

# Normal verileri 'normal.txt' dosyasına yazma
with open('testNORM.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(df['Sentence'][df['Label'] == 0]))

with open('testXSS.txt', 'r', encoding='utf-8') as f:
    testXSS = f.readlines()

with open('testNORM.txt', 'r', encoding='utf-8') as f:
    testNORM = f.readlines()


#----------------------------------------------------------------------------

print("*", sep=' ', end='', flush=True)
# parse out the query part of the URL 
for line in testXSS:
    query = parse.urlsplit(line)[3]
    #try to remove open redirect vulns
    if "?http" in str(line):
        continue
    if "?url=http" in str(line):
        continue
    if "?fwd=http" in str(line):
        continue
    if "?path=http" in str(line):
        continue
    if "=http" in str(query):
        continue
    if "page=search" in str(query):
        continue
    if len(query) > 8:
        xssnum += 1
        #X_temp.append(query)
        X_temp.append(line)
        
# remove duplicates
dedup = list(dict.fromkeys(X_temp))
print("*", sep=' ', end='', flush=True)
# Add a feature to X and label to the y array
for line in dedup:
    #print("XSS => "+line)
    X.append(line)
    y.append(1)
    
X_temp = []
dedup = []
print("*", sep=' ', end='', flush=True)


# parse out the query part of the URL 
for line in testNORM:
    query = parse.urlsplit(line)[3]
    #if "http" in str(query):
    #    continue
    if len(query) > 3:
        notxssnum += 1
        X_temp.append(line)
        
# remove duplicates
dedup = list(dict.fromkeys(X_temp))
print("*", sep=' ', end='', flush=True)
# Add a feature to X and a label to the y array
for line in dedup:
    #print("NOT XSS => "+line)
    X.append(line)
    y.append(0)


#print(X)
#vec2d = [X,y]
#print(vec2d)

print("Number of XSS Samples: "+str(xssnum))
print("Number of NOT XSS Samples: "+str(notxssnum))
print("Total Samples: "+str(xssnum+notxssnum))

# Create a function to convert an array of query strings to a set of features
# def getVec(text):
#     tagged_data = [TaggedDocument(words=word_tokenize(_d.lower()), tags=[str(i)]) for i, _d in enumerate(text)]
#     max_epochs = 25
#     vec_size = 20
#     alpha = 0.025
#     model = Doc2Vec(vector_size=vec_size,
#                 alpha=alpha, 
#                 min_alpha=0.00025,
#                 min_count=1,
#                 dm=1)
#     model.build_vocab(tagged_data)
#     print("Building the sample vector model...")
#     features = []
#     for epoch in range(max_epochs):
#         #print('Doc2Vec Iteration {0}'.format(epoch))
#         print("*", sep=' ', end='', flush=True)
#         model.random.seed(42)
#         model.train(tagged_data,
#                 total_examples=model.corpus_count,
#                 epochs=model.epochs)
#         # decrease the learning rate
#         model.alpha -= 0.0002
#         # fix the learning rate, no decay
#         model.min_alpha = model.alpha
#     model.save("d2v.model")
#     print()
#     print("Model Saved")
#     for i, line in enumerate(text):
#         featureVec = [model.dv[i]]
#         lineDecode = unquote(line)
#         lineDecode = lineDecode.replace(" ", "")
#         lowerStr = str(lineDecode).lower()
#         #print("X"+str(i)+"=> "+line)
#         # We could expand the features
#         # https://websitesetup.org/javascript-cheat-sheet/
#         # https://owasp.org/www-community/xss-filter-evasion-cheatsheet
#         # https://html5sec.org/
        
#         # add feature for malicious HTML tag count
#         feature1 = int(lowerStr.count('<link'))
#         feature1 += int(lowerStr.count('<object'))
#         feature1 += int(lowerStr.count('<form'))
#         feature1 += int(lowerStr.count('<embed'))
#         feature1 += int(lowerStr.count('<ilayer'))
#         feature1 += int(lowerStr.count('<layer'))
#         feature1 += int(lowerStr.count('<style'))
#         feature1 += int(lowerStr.count('<applet'))
#         feature1 += int(lowerStr.count('<meta'))
#         feature1 += int(lowerStr.count('<img'))
#         feature1 += int(lowerStr.count('<iframe'))
#         feature1 += int(lowerStr.count('<input'))
#         feature1 += int(lowerStr.count('<body'))
#         feature1 += int(lowerStr.count('<video'))
#         feature1 += int(lowerStr.count('<button'))
#         feature1 += int(lowerStr.count('<math'))
#         feature1 += int(lowerStr.count('<picture'))
#         feature1 += int(lowerStr.count('<map'))
#         feature1 += int(lowerStr.count('<svg'))
#         feature1 += int(lowerStr.count('<div'))
#         feature1 += int(lowerStr.count('<a'))
#         feature1 += int(lowerStr.count('<details'))
#         feature1 += int(lowerStr.count('<frameset'))
#         feature1 += int(lowerStr.count('<table'))
#         feature1 += int(lowerStr.count('<comment'))
#         feature1 += int(lowerStr.count('<base'))
#         feature1 += int(lowerStr.count('<image'))
#         # add feature for malicious method/event count
#         feature2 = int(lowerStr.count('exec'))
#         feature2 += int(lowerStr.count('fromcharcode'))
#         feature2 += int(lowerStr.count('eval'))
#         feature2 += int(lowerStr.count('alert'))
#         feature2 += int(lowerStr.count('getelementsbytagname'))
#         feature2 += int(lowerStr.count('write'))
#         feature2 += int(lowerStr.count('unescape'))
#         feature2 += int(lowerStr.count('escape'))
#         feature2 += int(lowerStr.count('prompt'))
#         feature2 += int(lowerStr.count('onload'))
#         feature2 += int(lowerStr.count('onclick'))
#         feature2 += int(lowerStr.count('onerror'))
#         feature2 += int(lowerStr.count('onpage'))
#         feature2 += int(lowerStr.count('confirm'))
#         feature2 += int(lowerStr.count('marquee'))
#         # add feature for ".js" count
#         feature3 = int(lowerStr.count('.js'))
#         # add feature for "javascript" count
#         feature4 = int(lowerStr.count('javascript'))
#         # add feature for length of the string
#         feature5 = int(len(lowerStr))
#         # add feature for "<script"  count
#         feature6 = int(lowerStr.count('<script'))
#         feature6 += int(lowerStr.count('&lt;script'))
#         feature6 += int(lowerStr.count('%3cscript'))
#         feature6 += int(lowerStr.count('%3c%73%63%72%69%70%74'))
#         # add feature for special character count
#         feature7 = int(lowerStr.count('&'))
#         feature7 += int(lowerStr.count('<'))
#         feature7 += int(lowerStr.count('>'))
#         feature7 += int(lowerStr.count('"'))
#         feature7 += int(lowerStr.count('\''))
#         feature7 += int(lowerStr.count('/'))
#         feature7 += int(lowerStr.count('%'))
#         feature7 += int(lowerStr.count('*'))
#         feature7 += int(lowerStr.count(';'))
#         feature7 += int(lowerStr.count('+'))
#         feature7 += int(lowerStr.count('='))
#         feature7 += int(lowerStr.count('%3C'))
#         # add feature for http count
#         feature8 = int(lowerStr.count('http'))
        
#         # append the features
#         featureVec = np.append(featureVec,feature1)
#         #featureVec = np.append(featureVec,feature2)
#         featureVec = np.append(featureVec,feature3)
#         featureVec = np.append(featureVec,feature4)
#         featureVec = np.append(featureVec,feature5)
#         featureVec = np.append(featureVec,feature6)
#         featureVec = np.append(featureVec,feature7)
#         #featureVec = np.append(featureVec,feature8)
#         #print(featureVec)
#         features.append(featureVec)
#     return features

def getVec(text):
    tagged_data = [TaggedDocument(words=word_tokenize(_d.lower()), tags=[str(i)]) for i, _d in enumerate(text)]
    
    # Kelime dağarcığını oluştur
    model = Doc2Vec(vector_size=20, alpha=0.025, min_alpha=0.00025, min_count=1, dm=1)
    model.build_vocab(tagged_data)
    
    max_epochs = 25
    for epoch in range(max_epochs):
        model.random.seed(42)
        model.train(tagged_data, total_examples=model.corpus_count, epochs=model.epochs)
        model.alpha -= 0.0002
        model.min_alpha = model.alpha
    
    model.save("d2v.model")
    print("Model Saved")
    
    features = []
    for i, line in enumerate(text):
        # Kelime dağarcığındaki bir kelimenin vektörünü al
        featureVec = model.infer_vector(word_tokenize(line.lower()))
        lineDecode = unquote(line)
        lineDecode = lineDecode.replace(" ", "")
        lowerStr = str(lineDecode).lower()
        #print("X"+str(i)+"=> "+line)
        # We could expand the features
        # https://websitesetup.org/javascript-cheat-sheet/
        # https://owasp.org/www-community/xss-filter-evasion-cheatsheet
        # https://html5sec.org/
        
        # add feature for malicious HTML tag count
        feature1 = int(lowerStr.count('<link'))
        feature1 += int(lowerStr.count('<object'))
        feature1 += int(lowerStr.count('<form'))
        feature1 += int(lowerStr.count('<embed'))
        feature1 += int(lowerStr.count('<ilayer'))
        feature1 += int(lowerStr.count('<layer'))
        feature1 += int(lowerStr.count('<style'))
        feature1 += int(lowerStr.count('<applet'))
        feature1 += int(lowerStr.count('<meta'))
        feature1 += int(lowerStr.count('<img'))
        feature1 += int(lowerStr.count('<iframe'))
        feature1 += int(lowerStr.count('<input'))
        feature1 += int(lowerStr.count('<body'))
        feature1 += int(lowerStr.count('<video'))
        feature1 += int(lowerStr.count('<button'))
        feature1 += int(lowerStr.count('<math'))
        feature1 += int(lowerStr.count('<picture'))
        feature1 += int(lowerStr.count('<map'))
        feature1 += int(lowerStr.count('<svg'))
        feature1 += int(lowerStr.count('<div'))
        feature1 += int(lowerStr.count('<a'))
        feature1 += int(lowerStr.count('<details'))
        feature1 += int(lowerStr.count('<frameset'))
        feature1 += int(lowerStr.count('<table'))
        feature1 += int(lowerStr.count('<comment'))
        feature1 += int(lowerStr.count('<base'))
        feature1 += int(lowerStr.count('<image'))
        # add feature for malicious method/event count
        feature2 = int(lowerStr.count('exec'))
        feature2 += int(lowerStr.count('fromcharcode'))
        feature2 += int(lowerStr.count('eval'))
        feature2 += int(lowerStr.count('alert'))
        feature2 += int(lowerStr.count('getelementsbytagname'))
        feature2 += int(lowerStr.count('write'))
        feature2 += int(lowerStr.count('unescape'))
        feature2 += int(lowerStr.count('escape'))
        feature2 += int(lowerStr.count('prompt'))
        feature2 += int(lowerStr.count('onload'))
        feature2 += int(lowerStr.count('onclick'))
        feature2 += int(lowerStr.count('onerror'))
        feature2 += int(lowerStr.count('onpage'))
        feature2 += int(lowerStr.count('confirm'))
        feature2 += int(lowerStr.count('marquee'))
        # add feature for ".js" count
        feature3 = int(lowerStr.count('.js'))
        # add feature for "javascript" count
        feature4 = int(lowerStr.count('javascript'))
        # add feature for length of the string
        feature5 = int(len(lowerStr))
        # add feature for "<script"  count
        feature6 = int(lowerStr.count('<script'))
        feature6 += int(lowerStr.count('&lt;script'))
        feature6 += int(lowerStr.count('%3cscript'))
        feature6 += int(lowerStr.count('%3c%73%63%72%69%70%74'))
        # add feature for special character count
        feature7 = int(lowerStr.count('&'))
        feature7 += int(lowerStr.count('<'))
        feature7 += int(lowerStr.count('>'))
        feature7 += int(lowerStr.count('"'))
        feature7 += int(lowerStr.count('\''))
        feature7 += int(lowerStr.count('/'))
        feature7 += int(lowerStr.count('%'))
        feature7 += int(lowerStr.count('*'))
        feature7 += int(lowerStr.count(';'))
        feature7 += int(lowerStr.count('+'))
        feature7 += int(lowerStr.count('='))
        feature7 += int(lowerStr.count('%3C'))
        # add feature for http count
        feature8 = int(lowerStr.count('http'))
        
        # append the features
        featureVec = np.append(featureVec,feature1)
        #featureVec = np.append(featureVec,feature2)
        featureVec = np.append(featureVec,feature3)
        featureVec = np.append(featureVec,feature4)
        featureVec = np.append(featureVec,feature5)
        featureVec = np.append(featureVec,feature6)
        featureVec = np.append(featureVec,feature7)
        #featureVec = np.append(featureVec,feature8)
        #print(featureVec)
        features.append(featureVec)
    return features

features = getVec(X)
features_dict = {'data':X,'features':features,'label':y}

#Features data

print("Test Sample: "+ X[0])
print("Features: " + str(features[0]))
print("\nLabel:\033[1;31;1m XSS(1)/\033[1;32;1m NOT XSS(0)\033[0;0m: " + str(y[0]))


#Train the model

np.random.seed(42)

from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(features, y, test_size = .3, random_state=42)

# Use RandomState for reproducibility.
from sklearn import tree
my_classifier1 = tree.DecisionTreeClassifier(random_state=42)
print(my_classifier1)
print()

from sklearn.svm import SVC
my_classifier2 = SVC(kernel='linear', random_state=42)
print(my_classifier2)
print()

from sklearn.naive_bayes import GaussianNB
my_classifier3 = GaussianNB()
print(my_classifier3)
print()

from sklearn.neighbors import KNeighborsClassifier
my_classifier4 = KNeighborsClassifier(n_neighbors=25, weights='uniform')
print(my_classifier4)
print()

from sklearn.ensemble import RandomForestClassifier
my_classifier5 = RandomForestClassifier(random_state=42)
print(my_classifier5)
print()

from sklearn.neural_network import MLPClassifier
my_classifier6 = MLPClassifier(max_iter=2000, random_state=42)
print(my_classifier6)
print()

#LOGISTIC REGRESSION ALGORITHM EKLENDİ.
from sklearn.linear_model import LogisticRegression
my_classifier7=LogisticRegression()
print(my_classifier7)
print()


X_train_flat = np.array(X_train).reshape(len(X_train), -1)
#X_train verileri X_train_flat yapıldı.Eski hali X_train .
print("Training Classifier #1 DecisionTreeClassifier")
my_classifier1.fit(X_train_flat, y_train)
print("Training Classifier #2 SVC")
my_classifier2.fit(X_train_flat, y_train)
print("Training Classifier #3 GaussianNB")
my_classifier3.fit(X_train_flat, y_train)
print("Training Classifier #4 KNeighborsClassifier")
my_classifier4.fit(X_train_flat, y_train)
print("Training Classifier #5 RandomForestClassifier")
my_classifier5.fit(X_train_flat, y_train)
print("Training Classifier #6 MLPClassifier")
my_classifier6.fit(X_train_flat, y_train)
print("Training Classifier #7 LogisticRegressionClassifier") #YENİ EKLENDİ
my_classifier7.fit(X_train_flat,y_train)




X_test_flat = np.array(X_test).reshape(len(X_test), -1)
#X_test_flat yeni eklendi.Eski çalışan hali X_test

predictions1 = my_classifier1.predict(X_test_flat)
predictions2 = my_classifier2.predict(X_test_flat)
predictions3 = my_classifier3.predict(X_test_flat)
predictions4 = my_classifier4.predict(X_test_flat)
predictions5 = my_classifier5.predict(X_test_flat)
predictions6 = my_classifier6.predict(X_test_flat)
predictions7 = my_classifier7.predict(X_test_flat)  #YENİ EKLENDİ.


#Training accuracy score

from sklearn.metrics import accuracy_score
print('Accuracy Score #1: {:.1%}'.format(accuracy_score(y_test, predictions1)))
print('Accuracy Score #2: {:.1%}'.format(accuracy_score(y_test, predictions2)))
print('Accuracy Score #3: {:.1%}'.format(accuracy_score(y_test, predictions3)))
print('Accuracy Score #4: {:.1%}'.format(accuracy_score(y_test, predictions4)))
print('Accuracy Score #5: {:.1%}'.format(accuracy_score(y_test, predictions5)))
print('Accuracy Score #6: {:.1%}'.format(accuracy_score(y_test, predictions6)))
print('Accuracy Score #7: {:.1%}'.format(accuracy_score(y_test, predictions7)))  #YENİ EKLENDİ.

#Classification Report

from sklearn.metrics import classification_report
print("Classification Report #1 DecisionTreeClassifier")
print(classification_report(y_test, predictions1))
print("Classification Report #2 SVC")
print(classification_report(y_test, predictions2))
print("Classification Report #3 GaussianNB")
print(classification_report(y_test, predictions3))
print("Classification Report #4 KNeighborsClassifier")
print(classification_report(y_test, predictions4))
print("Classification Report #5 RandomForestClassifier")
print(classification_report(y_test, predictions5))
print("Classification Report #6 MLPClassifier")
print(classification_report(y_test, predictions6))
print("Classification Report #7 LogisticRegressionClassifier")  #YENİ EKLENDİ.
print(classification_report(y_test, predictions7))


#Confusion Matrix

from sklearn.metrics import confusion_matrix
print("\nConfusion Matrix #1 DecisionTreeClassifier")
print(confusion_matrix(y_test, predictions1))
print("\nConfusion Matrix #2 SVC")
print(confusion_matrix(y_test, predictions2))
print("\nConfusion Matrix #3 GaussianNB")
print(confusion_matrix(y_test, predictions3))
print("\nConfusion Matrix #4 KNeighborsClassifier")
print(confusion_matrix(y_test, predictions4))
print("\nConfusion Matrix #5 RandomForestClassifier")
print(confusion_matrix(y_test, predictions5))
print("\nConfusion Matrix #6 MLPClassifier")
print(confusion_matrix(y_test, predictions6))
print("Classification Report #7 LogisticRegressionClassifier")  #YENİ EKLENDİ.
print(confusion_matrix(y_test, predictions7))

#Retrain the model with all the data

print("Training Classifier #1 DecisionTreeClassifier")
my_classifier1.fit(features, y)

print("Training Classifier #2 SVC")
my_classifier2.fit(features, y)

print("Training Classifier #3 GaussianNB")
my_classifier3.fit(features, y)

print("Training Classifier #4 KNeighborsClassifier")
my_classifier4.fit(features, y)

print("Training Classifier #5 RandomForestClassifier")
my_classifier5.fit(features, y)

print("Training Classifier #6 MLPClassifier")
my_classifier6.fit(features, y)

print("Training Classifier #7 LogisticRegressionClassifier")  #YENİ EKLENDİ.
my_classifier7.fit(features, y)


# save the model to disk
filename1 = 'DecisionTreeClassifier.sav'
pickle.dump(my_classifier1, open(filename1, 'wb'))

filename2 = 'SVC.sav'
pickle.dump(my_classifier2, open(filename2, 'wb'))

filename3 = 'GaussianNB.sav'
pickle.dump(my_classifier3, open(filename3, 'wb'))

filename4 = 'KNeighborsClassifier.sav'
pickle.dump(my_classifier4, open(filename4, 'wb'))

filename5 = 'RandomForestClassifier.sav'
pickle.dump(my_classifier5, open(filename5, 'wb'))

filename6 = 'MLPClassifier.sav'
pickle.dump(my_classifier6, open(filename6, 'wb'))

filename7 = 'LogisticRegression.sav'
pickle.dump(my_classifier7, open(filename7, 'wb'))   #YENİ EKLENDİ.


# load the model from disk

loaded_model1 = pickle.load(open(filename1, 'rb'))
loaded_model2 = pickle.load(open(filename2, 'rb'))
loaded_model3 = pickle.load(open(filename3, 'rb'))
loaded_model4 = pickle.load(open(filename4, 'rb'))
loaded_model5 = pickle.load(open(filename5, 'rb'))
loaded_model6 = pickle.load(open(filename6, 'rb'))
loaded_model7 = pickle.load(open(filename7, 'rb'))
