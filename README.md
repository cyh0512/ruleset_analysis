# ruleset_analysis
Analyze the ruleset and use data from different dimensions to create disjoint layers. The rules stored in each layer must be disjoint in a specific dimension and overlap will not occur.

// Source file說明:
all_sublayer_disjoint_5.cpp:
使用5-field建立layer

all_sublayer_disjoint_3.cpp:
使用srcIP+dstIP建立layer，如果有srcIP+dstIP cover range完全相同的rules，不視為overlapped，要放在同個layer。

all_sublayer_disjoint_edit_5.cpp:
使用5-field建立layer，removing all the rules whose source and dst IP fields are of length <= 5

all_sublayer_disjoint_edit_3.cpp:
使用srcIP+dstIP建立layer，removing all the rules whose source and dst IP fields are of length <= 5，如果有srcIP+dstIP cover range完全相同的rules，不視為overlapped，要放在同個layer。

// Compile in server 172:
g++ -std=c++11 all_sublayer_disjoint_edit_3.cpp -o all_sublayer_disjoint_edit_3
g++ -std=c++11 all_sublayer_disjoint_edit_5.cpp -o all_sublayer_disjoint_edit_5
g++ -std=c++11 all_sublayer_disjoint_3.cpp -o all_sublayer_disjoint_3
g++ -std=c++11 all_sublayer_disjointt_5.cpp -o all_sublayer_disjoint_5

// Run result，output結果會在./TABLE目錄下:
./all_sublayer_disjoint_5 ./TABLE/acl1_100K

// Or you can run script for all 12 rulesets:
./cpp_run_100k_data_5.sh
