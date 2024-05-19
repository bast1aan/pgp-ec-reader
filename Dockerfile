FROM maven:3.8-openjdk-18-slim

WORKDIR /srv
ADD pom.xml /srv/pom.xml

RUN mvn verify clean

ADD . /
RUN mvn package