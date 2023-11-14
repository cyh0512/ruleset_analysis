#include <iostream>
#include <fstream>
#include <vector>
#include <set>
#include <iterator>
#include <cstring>
#include <algorithm>
#include <math.h>
#include <string>
#define MAXDIMENSIONS 5

using namespace std;


struct range
{
    unsigned low;
    unsigned high;
};

struct pc_rule
{
    struct range field[MAXDIMENSIONS];
};
struct pc_rule *rule;
//struct pc_rule *rule_edit;

int ReadFile(const char *file_name);
bool is_disjoint(pc_rule *target_list, std::vector<int> *target_layer);
bool is_disjoint2(pc_rule *target_list, std::vector<int> *target_layer);
int rulesize=0;
int rulesize_edit=0;



int main(int argc,char *argv[])
{
    std::string dataset=argv[1];
    std::ofstream outputFile(dataset + "_output.txt");

    const char *fname=argv[1];
    ReadFile(fname);
    

    cout<<"Dataset: "<<argv[1]<<endl;
    cout<<"rulesize="<<rulesize<<endl;
    cout<<"rulesize_edit="<<rulesize_edit<<endl;
    cout<<rule[0].field[0].low<<"~"<<rule[0].field[0].high<<endl;
    cout<<rule[0].field[1].low<<"~"<<rule[0].field[1].high<<endl;
    cout<<rule[0].field[2].low<<"~"<<rule[0].field[2].high<<endl;
    cout<<rule[0].field[3].low<<"~"<<rule[0].field[3].high<<endl;
    cout<<rule[0].field[4].low<<"~"<<rule[0].field[4].high<<endl;


    //建立layer(使用srcIP)
    std::vector<std::vector<int>> layers;
    std::vector<int> temp;
    int done=0;

    layers.push_back(temp); //擴張layers[]至二維陣列
    layers[0].push_back(0); //第0條rule必定在第1層layer

    for(int i=1;i<rulesize_edit;i++){ //從第1條rule開始到第n-1個rule
        done=0;
        if(i%10000==0)
            cout<<"ID: "<<i<<endl;
        for(int j=0;j<layers.size();j++){ //每條rule從第1個layer開始比對，直到最後1層layer
            if(is_disjoint(&rule[i], &layers[j])){
                layers[j].push_back(i);
                done=1;
                break;
            }
        }
        if(done==0){
            layers.push_back(temp);
            layers[layers.size()-1].push_back(i);
        }
    }
    outputFile<<"結果:"<<"\n";

    outputFile<<"#num of rules = "<<rulesize<<"\n";
    outputFile<<"#num of rules after removing all the rules whose source and dst IP fields are of length <= 5 = "<<rulesize_edit<<"\n";
    //cout<<"結果:"<<endl;
    outputFile<<"#num of layers = "<<layers.size()<<"\n";
    for(int i=0;i<layers.size();i++){
        outputFile<<"#num of rules in Layer "<<i<<" :"<<layers[i].size()<<"\n";
        //cout<<"Layer "<<i<<" :"<<layers[i].size()<<endl;
    }

/*
    //根據第一次建的layer(只用第1維度(srcIP)判斷disjoint)，
    //再用第2維度(dstIP)對每個layer的rule建立sub-layer(這裡叫做new_layers)
    std::vector<std::vector<int>> new_layers;
    //std::vector<int> temp;

    for(int layer_cnt=0;layer_cnt<layers.size();layer_cnt++){ //從layer[0]開始建new_layer，一直到layer[n-1]結束。

        new_layers = std::vector<std::vector<int>>(); //初始化並清除new_layers
        temp = std::vector<int>(); //初始化並清除temp
        
        new_layers.push_back(temp);
        new_layers[0].push_back(layers[layer_cnt].at(0)); //new_layers[0]的首個rule一定是layers[layer_cnt]的第一條rule。

        for(int i=1;i<layers[layer_cnt].size();i++){ //對layer[i]儲存的每個rule做is_disjoint檢查。
            done=0;
            if(i%10000==0)
                cout<<"Sub-layer ID: "<<i<<endl;
            for(int j=0;j<new_layers.size();j++){
                if(is_disjoint(&rule[layers[layer_cnt].at(i)],&new_layers[j])){
                    new_layers[j].push_back(layers[layer_cnt].at(i));
                    done=1;
                    break;
                }
            }
            if(done==0){
                new_layers.push_back(temp);
                new_layers[new_layers.size()-1].push_back(layers[layer_cnt].at(i));
            }
        }

        //cout<<"Sub-layer build by layer "<<layer_cnt<< ": "<<endl;
        //cout<<"Sub-layer size= "<<new_layers.size()<<endl;
        //cout<<"#num of rules in Sub-layer i :"<<endl;
        //outputFile<<"Sub-layer build by layer "<<layer_cnt<< ": "<<"\n";
        //outputFile<<"Sub-layer size= "<<new_layers.size()<<"\n";
        //outputFile<<"#num of rules in Sub-layer i :"<<"\n";
        outputFile<<"#num of Sub-layers in layer"<<layer_cnt<<" :"<<new_layers.size()<<"\n";
        
        //for(int i=0;i<new_layers.size();i++){
        //    cout<<"Sub-layer "<<i<<" :"<<new_layers[i].size()<<endl;
        //}
        


    }
*/
    outputFile.close();
    return 0;
}


int ReadFile(const char *file_name)
{
    int i = 0;

    unsigned tmp;
    unsigned sip1, sip2, sip3, sip4, siplen;
    unsigned dip1, dip2, dip3, dip4, diplen;
    unsigned sport_low, sport_high;
    unsigned dport_low, dport_high;
    unsigned proto, protomask;
    unsigned per, deny;
    char validator,status;
    FILE *fp;
    fp=fopen(file_name,"r");

    while (1)   //count how many entries are there in the classifier file
    {
        status=fscanf(fp,"%c",&validator);

        if (status==EOF)
            break;

        if (validator!='@')
            continue;

        rulesize++;
    }

    rewind(fp);

    //注意:struct pc_rule[rulesize]裡面只存了rulesize_edit個元素，取sizeof的時候要注意。
    rule = new struct pc_rule[rulesize];
    for (i=0; i<rulesize; i++)
    {

        /*if (fscanf(fp,"@%d.%d.%d.%d/%d\t%d.%d.%d.%d/%d\t%d : %d\t%d : %d\t%x/%x\t%x/%x\t\n",
                   &sip1, &sip2, &sip3, &sip4, &siplen, &dip1, &dip2, &dip3, &dip4, &diplen,
                   &rule[i].field[2].low, &rule[i].field[2].high, &rule[i].field[3].low, &rule[i].field[3].high,
                   &proto, &protomask,&per,&deny) != 18) break;
        */

        fscanf(fp,"@%d.%d.%d.%d/%d\t%d.%d.%d.%d/%d\t%d : %d\t%d : %d\t%x/%x\t%x/%x\t\n",
               &sip1, &sip2, &sip3, &sip4, &siplen, &dip1, &dip2, &dip3, &dip4, &diplen,
               &sport_low, &sport_high, &dport_low, &dport_high,
               &proto, &protomask,&per,&deny);
        
        if((siplen>5) || (diplen>5)){

            

            rule[rulesize_edit].field[2].low=sport_low;
            rule[rulesize_edit].field[2].high=sport_high;
            rule[rulesize_edit].field[3].low=dport_low;
            rule[rulesize_edit].field[3].high=dport_high;

            if (siplen == 0)
            {
                rule[rulesize_edit].field[0].low = 0;
                rule[rulesize_edit].field[0].high = 0xFFFFFFFF;
            }
            else if (siplen > 0 && siplen <= 8)
            {
                tmp = sip1>>(8-siplen);
                tmp=tmp<<(32-siplen);
                rule[rulesize_edit].field[0].low = tmp;
                rule[rulesize_edit].field[0].high = rule[rulesize_edit].field[0].low + ((1<<(32-siplen)) - 1);

            }
            else if (siplen > 8 && siplen <= 16)
            {
                tmp = sip1<<24;
                tmp += sip2<<16;
                rule[rulesize_edit].field[0].low = tmp;
                rule[rulesize_edit].field[0].high = rule[rulesize_edit].field[0].low + (1<<(32-siplen)) - 1;
            }
            else if (siplen > 16 && siplen <= 24)
            {
                tmp = sip1<<24;
                tmp += sip2<<16;
                tmp +=sip3<<8;
                rule[rulesize_edit].field[0].low = tmp;
                rule[rulesize_edit].field[0].high = rule[rulesize_edit].field[0].low + (1<<(32-siplen)) - 1;
            }
            else if (siplen > 24 && siplen <= 32)
            {
                tmp = sip1<<24;
                tmp += sip2<<16;
                tmp += sip3<<8;
                tmp += sip4;
                rule[rulesize_edit].field[0].low = tmp;
                rule[rulesize_edit].field[0].high = rule[rulesize_edit].field[0].low + (1<<(32-siplen)) - 1;

            }
            else
            {
                printf("Src IP length exceeds 32\n");
                return 0;
            }

            if (diplen == 0)
            {
                rule[rulesize_edit].field[1].low = 0;
                rule[rulesize_edit].field[1].high = 0xFFFFFFFF;
            }
            else if (diplen > 0 && diplen <= 8)
            {
                tmp = dip1>>(8-diplen);
                tmp=tmp<<(32-diplen);

                rule[rulesize_edit].field[1].low = tmp;
                rule[rulesize_edit].field[1].high = rule[rulesize_edit].field[1].low + ((1<<(32-diplen)) - 1);



            }
            else if (diplen > 8 && diplen <= 16)
            {
                tmp = dip1<<24;
                tmp +=dip2<<16;
                rule[rulesize_edit].field[1].low = tmp;
                rule[rulesize_edit].field[1].high = rule[rulesize_edit].field[1].low + (1<<(32-diplen)) - 1;
            }
            else if (diplen > 16 && diplen <= 24)
            {
                tmp = dip1<<24;
                tmp +=dip2<<16;
                tmp+=dip3<<8;
                rule[rulesize_edit].field[1].low = tmp;
                rule[rulesize_edit].field[1].high = rule[rulesize_edit].field[1].low + (1<<(32-diplen)) - 1;
            }
            else if (diplen > 24 && diplen <= 32)
            {
                tmp = dip1<<24;
                tmp +=dip2<<16;
                tmp+=dip3<<8;
                tmp +=dip4;
                rule[rulesize_edit].field[1].low = tmp;
                rule[rulesize_edit].field[1].high = rule[rulesize_edit].field[1].low + (1<<(32-diplen)) - 1;
            }
            else
            {
                printf("Dest IP length exceeds 32\n");
                return 0;
            }

            if (protomask == 0xFF)
            {
                rule[rulesize_edit].field[4].low = proto;
                rule[rulesize_edit].field[4].high = proto;
            }
            else if (protomask == 0)
            {
                rule[rulesize_edit].field[4].low = 0;
                rule[rulesize_edit].field[4].high = 0xFF;
            }
            else
            {
                printf("Protocol mask error\n");
                return 0;
            }

            rulesize_edit++;
        }
    }
    rewind(fp); //讓fp回到檔案開頭

    return rulesize_edit;
}

bool is_disjoint(pc_rule* target_list, std::vector<int>* target_layer){
    int cover=0;
    //int target_layer_num=0;
    int range_all_same=0;

    for(int i=0;i<2;i++){
        cover=0;
        for(int k=0; k < target_layer->size();k++){
            if(i==0){ //判斷是否在該layer有rule，和自己的srcIP、dstIP兩個field的range都相同，則當作同一條rule，放在同個layer。
                if((target_list->field[i].low == rule[target_layer->at(k)].field[i].low) && 
                (target_list->field[i].high == rule[target_layer->at(k)].field[i].high) && 
                (target_list->field[i+1].low == rule[target_layer->at(k)].field[i+1].low) && 
                (target_list->field[i+1].high == rule[target_layer->at(k)].field[i+1].high)){
                    range_all_same=1;
                    break;
                }
            }

            //target_layer_num = target_layer->at(k); //這裡使用.at()而非[]
            //rule跟target_layer之中的所有rule比較，與任何rule的field有overlap，則cover=1，break後繼續比較下個field。
            if((target_list->field[i].low < rule[target_layer->at(k)].field[i].low) && (target_list->field[i].high > rule[target_layer->at(k)].field[i].low)){
                cover=1;
                break;
            }
            else if ((target_list->field[i].low > rule[target_layer->at(k)].field[i].low) && (target_list->field[i].low < rule[target_layer->at(k)].field[i].high)){
                cover=1;
                break;
            }
            else if (target_list->field[i].low == rule[target_layer->at(k)].field[i].low){
                cover=1;
                break;
            }
        }

        if(range_all_same==1) //找到同layer有rule，和自己的srcIP、dstIP兩個field的range都相同，則當作同一條rule，放在同個layer。
            return true;
        if(cover==0)
            return true;
    }

    return false;
}
/*

bool is_disjoint2(pc_rule* target_list, std::vector<int>* target_layer){
    int cover=0;
    //int target_layer_num=0;
    for(int i=1;i<2;i++){
        cover=0;
        for(int k=0; k < target_layer->size();k++){
            //target_layer_num = target_layer->at(k); //這裡使用.at()而非[]
            if((target_list->field[i].low < rule[target_layer->at(k)].field[i].low) && (target_list->field[i].high > rule[target_layer->at(k)].field[i].low)){
                cover=1;
                break;
            }
            else if ((target_list->field[i].low > rule[target_layer->at(k)].field[i].low) && (target_list->field[i].low < rule[target_layer->at(k)].field[i].high)){
                cover=1;
                break;
            }
            else if (target_list->field[i].low == rule[target_layer->at(k)].field[i].low){
                cover=1;
                break;
            }
        }
        if(cover==0)
            return true;
    }
    return false;
}

*/