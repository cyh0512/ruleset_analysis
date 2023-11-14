import math
import random
import numpy as np
import re
import sys



def load_rules_from_file(file_name):
    rules = []
    rule_fmt = re.compile(r'^@(\d+).(\d+).(\d+).(\d+)/(\d+) '\
        r'(\d+).(\d+).(\d+).(\d+)/(\d+) ' \
        r'(\d+) : (\d+) ' \
        r'(\d+) : (\d+) ' \
        r'(0x[\da-fA-F]+)/(0x[\da-fA-F]+) ' \
        r'(.*?)')
    for idx, line in enumerate(open(file_name)):
        elements = line[1:-1].split('\t')
        line = line.replace('\t', ' ')

        sip0, sip1, sip2, sip3, sip_mask_len, \
        dip0, dip1, dip2, dip3, dip_mask_len, \
        sport_begin, sport_end, \
        dport_begin, dport_end, \
        proto, proto_mask = \
        (eval(rule_fmt.match(line).group(i)) for i in range(1, 17))

        sip0 = (sip0 << 24) | (sip1 << 16) | (sip2 << 8) | sip3
        sip_begin = sip0 & (~((1 << (32 - sip_mask_len)) - 1))
        sip_end = sip0 | ((1 << (32 - sip_mask_len)) - 1)

        dip0 = (dip0 << 24) | (dip1 << 16) | (dip2 << 8) | dip3
        dip_begin = dip0 & (~((1 << (32 - dip_mask_len)) - 1))
        dip_end = dip0 | ((1 << (32 - dip_mask_len)) - 1)

        if proto_mask == 0xff:
            proto_begin = proto
            proto_end = proto
        else:
            proto_begin = 0
            proto_end = 0xff
        if (sip_mask_len>5 or dip_mask_len>5):
            rules.append(
            [
              sip_begin, sip_end, dip_begin, dip_end, sport_begin,
              sport_end, dport_begin, dport_end, proto_begin,
              proto_end
            ])
    return rules

def is_disjoint(target_list,target_layer):
  for i in range(1):
    cover = 0
    for k in range(len(target_layer)): #rules[target_layer[k][2*i]]  
      #print(target_list[2*i]) #a
      #print(target_list[2*i+1]) #b
      #print(rules[target_layer[k]][2*i]) #c
      #print(rules[target_layer[k]][2*i+1]) #d
      #print("---")
      if(target_list[2*i]<rules[target_layer[k]][2*i] and target_list[2*i+1]>rules[target_layer[k]][2*i]):
        cover = 1
        break
      elif(target_list[2*i]>rules[target_layer[k]][2*i] and target_list[2*i]<rules[target_layer[k]][2*i+1]):
        cover = 1
        break
      elif(target_list[2*i]==rules[target_layer[k]][2*i]):
        cover = 1 
        break
    if(cover==0):
      return True
  return False

def is_disjoint2(target_list,target_layer): #用第二個維度(dstIP)判斷是否disjoint
  for i in range(1,2):
    cover = 0
    for k in range(len(target_layer)): #rules[target_layer[k][2*i]]  
      #print(target_list[2*i]) #a
      #print(target_list[2*i+1]) #b
      #print(rules[target_layer[k]][2*i]) #c
      #print(rules[target_layer[k]][2*i+1]) #d
      #print("---")
      if(target_list[2*i]<rules[target_layer[k]][2*i] and target_list[2*i+1]>rules[target_layer[k]][2*i]):
        cover = 1
        break
      elif(target_list[2*i]>rules[target_layer[k]][2*i] and target_list[2*i]<rules[target_layer[k]][2*i+1]):
        cover = 1
        break
      elif(target_list[2*i]==rules[target_layer[k]][2*i]):
        cover = 1 
        break
    if(cover==0):
      return True
  return False


#main
script, file_name = sys.argv
rules = []
rules = load_rules_from_file(file_name)

print("")
print("Dataset:",file_name)
print("Num of rules=",len(rules))

layers = [] #layer從0開始算到n-1
temp = []


#建立layer
layers.append(temp) #擴張layers[]至二維陣列
layers[len(layers)-1].append(0) #第0條rule必定在第1層layer

for i in range(1,len(rules)): #從第1條rule開始到第n-1個rule
  done = 0
  if((i%10000)==0):
    print("ID :",i)
  for j in range(len(layers)): #每條rule從第1個layer開始比對，直到最後1層layer
    if(is_disjoint(rules[i],layers[j])): #與該層layer的所有rule比對是否disjoint，如果有一個維度disjoint，該rule就留在同一層layer。
      layers[j].append(i)
      done = 1
      break
  if(done==0): #比對到最後1層layer，如果還是都overlap，就再往下增加1層layer。
    temp = []
    layers.append(temp)
    layers[len(layers)-1].append(i)

print("結果:")  
for i in range(len(layers)):
  print("Layer:",i,len(layers[i]))



#根據第一次建的layer(只用第1維度(srcIP)判斷disjoint)，再用第2維度(dstIP)對每個layer(目前先對第1層layer來做)的rule建立sub-layer
new_layers = [] #layer從0開始算到n-1
temp = []

new_layers.append(temp)
new_layers[len(new_layers)-1].append(layers[0][0]) #rule 0必定在layer 0，但sub-layer 0的首個rule不一定是rule 0
for i in range(1,len(layers[0])): #從原layer第一層的 第1條rule開始到第n-1個rule
  done=0
  if((i%10000)==0):
    print("sub-layer ID:",i)
  for j in range(len(new_layers)):
    if(is_disjoint2(rules[layers[0][i]],new_layers[j])):
      new_layers[j].append(layers[0][i])
      done = 1
      break
  if(done==0):
    temp=[]
    new_layers.append(temp)
    new_layers[len(new_layers)-1].append(layers[0][i])

print("Sub-layer結果:")
for i in range(len(new_layers)):
  print("sub-layer:",i,len(new_layers[i]))