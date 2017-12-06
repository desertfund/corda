Default Class Evolution
=======================

.. contents::

Whilst more complex evolutionary modifications to classes require annotating, Corda's serialization
framework supports several minor modifications to classes without any external modification save
the actual code changes. These are:

    #.  Adding nullable properties
    #.  Adding non nullable properties *IFF* an annotated constructor is provided
    #.  Removing properties
    #.  Reordering constructor parameters

Adding Nullable Properties
--------------------------

The serialization framework allows nullable properties to be freely added. For example:

.. container:: codeset

   .. sourcecode:: kotlin

        // Initial instance of the class
        data class Example1 (val a: Int, b: String) // (A)


        // Class post addition of property c
        data class Example1 (val a: Int, b: String, c: Int?) // (B)

A node with class Example1 in state A will be able to deserialize a blob serialized by a node with it
in state B as the framework would treat it as a removed property

A node with the class in state B will be able to deserialize a serialized Example1 in state A without
any modification as the property is nullable and will thus provide null to the constructor

Adding Non Nullable Properties
------------------------------

If a non null property is added, unlike nullable properties, some additional code is required for
this to work. Consider a similar example to our nullable example above

.. container:: codeset

   .. sourcecode:: kotlin

        // Initial instance of the class
        data class Example2 (val a: Int, b: String) // (A)


        // Class post addition of property c
        data class Example1 (val a: Int, b: String, c: Int) { // (B)
             @DeprecatedConstructorForDeserialization(1)
             constructor (a: Int, b: String) : this(a, b, 0) // 0 has been determind as a sensible default

        }

For this to work we have had to add a new constructor that allows nodes in state B to create an instance from
a serialised form of A. A sensible default for the missing value is provided for instantiation of the non
null property

.. note:: The ``@DeprecatedConstructorForDeserialization`` annotation is important, this signifies to the
    serialization framework that this constructor should be considered for building instances of the
    object when evolution is required.

    Furthermore, the integer parameter passed to the constructor indicates a precedence order, see the
    discussion below

As before, instances of state A will be able to deserialize serialized forms of state B as it will simply
treat them as if the property has been removed (As from it's perspective, they will have been)


Constructor Versioning
~~~~~~~~~~~~~~~~~~~~~~

If, over time, multiple non nullable properties are added, then a class will potentially have to be able
to deserialize a number of different forms of the class. Being able to select the correct constructor is
important to ensure the maximum information is extracted.

Consider this example:


.. container:: codeset

   .. sourcecode:: kotlin

        // The original version of the class
        data class Example3 (val a: Int, val b: Int)

.. container:: codeset

   .. sourcecode:: kotlin

        // The first alteration, property c added
        data class Example3 (val a: Int, val b: Int, val c: Int)

.. container:: codeset

   .. sourcecode:: kotlin

        // The second alteration, property d added
        data class Example3 (val a: Int, val b: Int, val c: Int, val d: Int)

.. container:: codeset

   .. sourcecode:: kotlin

        // The third alteration, and how it currently exists, property e added
        data class Example3 (val a: Int, val b: Int, val c: Int, val d: Int, val: Int e) {
            // NOTE: version number purposefully omitted from annotation for demonstration purposes
            @DeprecatedConstructorForDeserialization constructor (a: Int, b: Int) : this(a, b, -1, -1, -1)          // alt constructor 1
            @DeprecatedConstructorForDeserialization constructor (a: Int, b: Int, c: Int) : this(a, b, c, -1, -1)   // alt constructor 2
            @DeprecatedConstructorForDeserialization constructor (a: Int, b: Int, c: Int, d) : this(a, b, c, d, -1) // alt constructor 3
        }

In this case, the deserialiger has to be able to deserialize instances of class Example3 that were serialized as, for example:

.. container:: codeset

   .. sourcecode:: kotlin

        Example3 (1, 2)             // example I
        Example3 (1, 2, 3)          // example II
        Example3 (1, 2, 3, 4)       // example III
        Example3 (1, 2, 3, 4, 5)    // example IV

Examples I, II, and III would require evolution and thus selection of constructor. Now, with no versioning applied there
is ambiguity as to which constructor should be used. For example, example II could use 'alt constructor 2' which matches
it's arguments most tightly or 'alt constructor 1' and not instantiate parameter c.

``constructor (a: Int, b: Int, c: Int) : this(a, b, c, -1, -1)``

or

``constructor (a: Int, b: Int, c: Int) : this(a, b, c, -1, -1)``

Whilst it may seem trivial which should be picked, it is still ambiguous, thus we use a versioning number in the constructor
annotation which gives a strict precedence order to constructor selection. Therefore, the proper form of the example would
be:

.. container:: codeset

   .. sourcecode:: kotlin

        // The third alteration, and how it currently exists, property e added
        data class Example3 (val a: Int, val b: Int, val c: Int, val d: Int, val: Int e) {
            // NOTE: version number purposefully omitted from annotation for demonstration purposes
            @DeprecatedConstructorForDeserialization(1) constructor (a: Int, b: Int) : this(a, b, -1, -1, -1)          // alt constructor 1
            @DeprecatedConstructorForDeserialization(2) constructor (a: Int, b: Int, c: Int) : this(a, b, c, -1, -1)   // alt constructor 2
            @DeprecatedConstructorForDeserialization(3) constructor (a: Int, b: Int, c: Int, d) : this(a, b, c, d, -1) // alt constructor 3
        }

Constructors are selected in strict descending order taking the one that enables construction. So, deserializing examples I to IV would
give us

.. container:: codeset

   .. sourcecode:: kotlin

        Example3 (1, 2, -1, -1, -1) // example I
        Example3 (1, 2, 3, -1, -1)  // example II
        Example3 (1, 2, 3, 4, -1)   // example III
        Example3 (1, 2, 3, 4, 5)    // example IV

Removing Properties
-------------------

Property removal is effectively a mirror of adding properties (both nullable and non nullable) given it is required to facilitate
the addition of properties. When this state is detected by the serialization framework, properties that don't have matching
parameters in the main constructor are simply omitted from objected construction

.. container:: codeset

   .. sourcecode:: kotlin

        // Initial instance of the class
        data class Example2 (val a: Int, b: String) // (A)


        // Class post removal of property a
        data class Example1 (String, c: Int) { // (B)


Reordering Constructor Parameter Order
--------------------------------------

Properties (in Kotlin this corresponds to constructor parameters) may be reordered freely. The evolution serializer will create a
mapping between how a class was serialized and it's current constructor order. For example:

.. container:: codeset

   .. sourcecode:: kotlin

        


Unsupported Evolutions
----------------------
