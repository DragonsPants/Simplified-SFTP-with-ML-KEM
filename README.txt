Hello, my name is Ryan Johnston.
This repository includes my graduate project for CIS6372 Information Assurance which
I will simply label S-SFTP with ML-KEM.
This project modifies Simplified-SFTP such that it performs key establishment using the Module-
Lattice-Based Key-Encapsulation Mechanism (ML-KEM) standard discribed in FIPS 203.

The original creators of Simplified-SFTP are Varun Balawade and Anusha Pai.
I will attempt to comment wherever I have made modifications, but by default credit goes to them.
Apoligies for not using Git in to track my changes in the first place.

Instructions for how to compile and run Simplified-SFTP can be found in README-old.md, which is
the original README file for Simplified-SFTP.
Running S-SFTP with ML-KEM is identical to running Simplified-SFTP, as ML-KEM requires no user input
to run.

In order to run the test I performed to confirm that S-SFTP still runs properly with ML-KEM,
you can run the following commands in order on seperate terminals after running cmake
./receiver.out -f testfile-copy.txt 
./sender.out -f testfile.txt 
This should produce a file labeled testfile-copy.txt which is identical to the original testfile
Alternatively, you can run Simplified-SFTP with the original creators test cases.

If you wish to see the outputs for ML-KEM you can run 
./tester.out
This will display an example output of ML-KEM by running KeyGen, Encaps, and Decaps and printing the output contents and length
Alternatively, you can use
./test.sh
which will automatically run cmake before running tester.out