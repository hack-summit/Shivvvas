import pandas as pd
import numpy as np
import random


from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

import pickle

def sanitization(web):                      # tokenizing method
    web = web.lower()
    token = []
    dot_token_slash = []
    raw_slash = str(web).split('/')
    for i in raw_slash:
        raw1 = str(i).split('-')            # removing slash to get token
        slash_token = []
        for j in range(0,len(raw1)):
            raw2 = str(raw1[j]).split('.')  # removing dot to get the tokenS
            slash_token = slash_token + raw2
        dot_token_slash = dot_token_slash + raw1 + slash_token # all tokens
    token = list(set(dot_token_slash))      # to remove same words  
    if 'com' in token:
        token.remove('com')                 # remove com
    return token

urls = ['hackthebox.eu','www.pakistanifacebook.com','stackoverflow.com','facebook.com']#,'google.com/search=VAD3R','wikipedia.co.uk'

file = "pickel_model.pkl"
with open(file, 'rb') as f1:  
    lgr = pickle.load(f1)
f1.close()
file = "pickel_vector.pkl"
with open(file, 'rb') as f2:  
    vectorizer = pickle.load(f2)
f2.close()
vectorizer = vectorizer
x = vectorizer.transform(urls)
#score = lgr.score(x_test, y_test)
y_predict = lgr.predict(x)
print(urls)
print(y_predict)
