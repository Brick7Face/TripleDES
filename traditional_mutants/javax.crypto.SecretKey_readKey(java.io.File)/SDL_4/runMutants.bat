    @ECHO OFF
    javac TestTripleDES.java
	javac TestRunner.java
	java TestRunner | find /c /v ""