def findMaxPathLength(path):
    max = 0
    file = open(path,"r")
    for line in file:
        list = line.split(" ")[1:]
        s = " "
        curr = s.join(list)
        temp=len(curr.split("|"))
        if(temp>max):
            max=temp
    file.close()
    return max
num1:int = findMaxPathLength("datasets/cfg_overfitting_test/valid_output.txt")
num2:int = findMaxPathLength("datasets/cfg_overfitting_test/test_output.txt")
num3:int = findMaxPathLength("datasets/cfg_overfitting_test/train_output.txt")
if(num1>=num2 and num1>=num3):
    print(num1)
if(num2>=num1 and num2>=num3):
    print(num2)
if(num3>=num1 and num3>=num2):
    print(num3)