# Automatic functionality recognition in a binary 

Steps to run the model:
1. Run ./run_exps.sh to execute main.py on all the binaries
2. Run generate_output from the command line using:
	python -c 'from main import generate_output; generate_output("datasets/cfg_overfitting_test")'
  redirecting output to a file out.txt
3. Run ./MaxPathLength.sh to get the maximum number of tokens(names) in a path in the output
4. Edit code2seq/config.py with the relevant output of ./MaxPathLength.sh
5. Run code2seq/preprocess.sh, saving the output
6. Edit config.py again, but this time with preprocess.sh output
7. Run train.sh

Optional: in case you need an implementation of callsites, take a look at LoopCallsites script.



