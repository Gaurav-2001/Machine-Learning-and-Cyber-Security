import os
import numpy as np
import pandas as pd
import plotly.graph_objs as go
import plotly.offline as pyof
import csv
import plotly.express as pxp
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
#importing dataset from file
dataset= pd.read_csv('/root/HTTPD_log.csv', names= ['IP', 'identd', 'user_id', 'time', 'time_ext','req_method', 'req_dir', 'req_http_header', 'status_code', 'bytes_trans'])
#we only need the IP Address & Status Code
dataset= dataset[['IP','status_code']]
#modifying dataset by aggregating count of status code against IP Address
dataset= dataset.groupby(['IP','status_code']).status_code.agg('count').to_frame('Total').reset_index()
#We are inserting the Index No as it needs it, otherwise it will give Shape of passed values is (13, 2), indices imply (13, 3) error
dataset.insert(0, 'IndexNo', range(len(dataset)))
#we are droping IP Column as instead of this we will take the Index No as reference of IP and scale it
train_data= dataset.drop(['IP'], axis= 1)

sc= StandardScaler()
scaled_data= sc.fit_transform(train_data)
#We have used here 3 as a cluster because it's a good practice to give odd number due to the calculation of points which are crucial between two cluster
#This solely depends and varry from data to data
model= KMeans(n_clusters= 3)
pred= model.fit_predict(scaled_data)
#here IP_Scaled is actually IndexNo because IP Address is treated as string
pred_ds= pd.DataFrame(scaled_data, columns= ['IP_Scaled', 'status_code_Scaled','Total_Scaled'])
pred_ds['Cluster']= pred
ds= pd.concat([dataset, pred_ds], axis= 1, sort= False)
#Here we are creating graph of Request per IP vs Count
Graph= pxp.scatter(ds, 'Total', 'IP', 'Cluster', hover_data= ['status_code'], color_continuous_scale= 'Jet') 
layout= go.Layout(title= 'Request/IP', hovermode= 'closest') 
figure= go.Figure(data= Graph, layout= layout)
graph= pyof.plot(figure, filename= 'Cluster_graph.html', auto_open= False)
#Here we will see which cluster is violating the number of request against a threshold of 500 
black_cluster= []
for index, row in ds.iterrows():
    if ds['Total'].loc[index] > 500:
          black_cluster.append(ds['Cluster'].loc[index])
black_cluster= max(set(black_cluster), key= black_cluster.count)
#Here we have created a CSV file which will keep record for all the IP which are under blacklist cluster
filename= "DoS_Blacklist.csv"
with open(filename, '+w') as csvfile:
    csvwriter = csv.writer(csvfile)
    csvwriter.writerow(['IP_Blacklist']) 
    for index_in_data, row_in_data in ds.iterrows():
        if ds['Cluster'].loc[index_in_data] == black_cluster:
            #Check whether we have the IP already in the file
            if ds['IP'].loc[index_in_data] not in np.array(csvfile): 
                csvwriter.writerows([[ds['IP'].loc[index_in_data]]])
                print("Blocking IP {0}".format(ds['IP'].loc[index_in_data]))
                #Blocking IP Address by writing a rule in iptables
                os.system("systemctl start firewalld")
                os.system("iptables -A INPUT -s {0} -j DROP".format(ds['IP'].loc[index_in_data]))
