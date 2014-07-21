#select
- directive in module ng
HTML SELECT element with angular data-binding.

###ngOptions
The ngOptions attribute can be used to dynamically generate a list of <option> elements for the <select> element using the array or object obtained by evaluating the ngOptions comprehension_expression.

When an item in the <select> menu is selected, the array element or object property represented by the selected option will be bound to the model identified by the ngModel directive.

Note: ngModel compares by reference, not value. This is important when binding to an array of objects. See an example in this jsfiddle.
Optionally, a single hard-coded <option> element, with the value set to an empty string, can be nested into the <select> element. This element will then represent the null or "not selected" option. See example below for demonstration.

Note: ngOptions provides an iterator facility for the <option> element which should be used instead of ngRepeat when you want the select model to be bound to a non-string value. This is because an option element can only be bound to string values at present.
