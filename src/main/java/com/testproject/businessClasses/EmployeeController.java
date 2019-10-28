package com.testproject.businessClasses;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path="/employees")
public class EmployeeController {

    @RequestMapping(value="/", method = RequestMethod.GET)
    public Object getEmployees(){
        return null;
    }
}
