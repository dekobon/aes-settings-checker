#!/usr/bin/env sh

java -version 2>&1 | tee debug.log
java -server -XX:+PrintFlagsFinal -jar ./target/aes-debugger-1.0-SNAPSHOT-jar-with-dependencies.jar debug.log 2>&1 | tee info.log
