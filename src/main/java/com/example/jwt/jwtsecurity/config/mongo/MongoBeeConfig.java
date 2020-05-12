package com.example.jwt.jwtsecurity.config.mongo;

import com.mongodb.MongoClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.data.mongodb.core.MongoTemplate;

import com.github.mongobee.Mongobee;

@Configuration
@DependsOn("mongoTemplate")
public class MongoBeeConfig {

    private static final String MONGODB_URL_FORMAT = "mongodb://%s:%s@%s:%d/%s";
    private static final String MONGODB_CHANGELOGS_PACKAGE = "com.example.jwt.jwtsecurity.config.mongo.changelogs";

    @Autowired
    private MongoProperties mongoProperties;

    @Autowired
    private MongoTemplate mongoTemplate;

    @Bean
    public Mongobee mongobee() {
        Mongobee runner = new Mongobee("mongodb://localhost:27017/JwtSpringbootDB");
        runner.setMongoTemplate(mongoTemplate);
        runner.setChangeLogsScanPackage(MONGODB_CHANGELOGS_PACKAGE);
        return runner;
    }

}
