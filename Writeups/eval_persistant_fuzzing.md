# B-Tier Fuzzing Performance with D-Tier Reverse Engineering: Using Native Control-Flow Primitives for Persistant Fuzzing

**BLUF**: When fuzzing embedded JS engines (or any other language) where you don't want to invest time reverse engineering and harnessing the engine itself _OR_ when you want to fuzz native APIs the target exposes to the engine, you can use a `while()` loop and `eval()` to execute your test cases fast(er) than restarting the program every iteration.

## Background
I'm working on fuzzing a PDF reader and have been wanting to get better performance.

I have provided a PDF which has a startup JS script that just calls `beep`.

<img width="506" height="39" alt="image" src="https://github.com/user-attachments/assets/4f241789-d26a-42a2-8253-b8b4a204959b" />

It takes 329 ms for my engine to get to running my `beep`. Restarting for every input means I would be getting only 3 executions per second, which is really slow.

Here's a snippet from an early version of my rudimentary JS self-fuzzer which randomly picks different JS grammar symbols to expand and generates a script (kind of like a inverse recursive-descent parser):
```js
...
fuzzer.prototype.generateStatement = function(depth) {
    var self = this;
    if (depth > this.depthLimit) {
        return this.getExistingOrNewVariable(true) + ' = ' + this.generatePrimitive() + ';';
    }

    var statementTypes = [
        function() { return self.generateDeclaration(depth); },
        function() { return self.generateLegacyAccessor(depth); },
        function() { return self.generateObjectMutation(depth); },
        function() { return self.generateControlFlow(depth); },
        function() { return self.getExistingOrNewVariable(true) + ' = ' + self.generateExpression(depth) + ';'; }
    ];

    return this.randomChoice(statementTypes)();
};

fuzzer.prototype.generateStatementBlock = function(depth) {
    var statementCount = Math.floor(random_number() * 3) + 1;
    var block = '';
    for (var i = 0; i < statementCount; i++) {
        block += this.generateStatement(depth) + '\n';
    }
    return block;
};

fuzzer.prototype.generateScript = function() {
    this.variablePool = []; 

    this.createVariable();
    this.createVariable();

    var script = '(function() {\n';
    script += this.generateStatementBlock(0);
    script += '})();\n';

    return script;
};

fuzzer.prototype.runFuzzLoop = function(iterations) {
    var executed = 0;
    var exceptions = 0;

    for (var i = 0; i < iterations; i++) {
        var code = this.generateScript();
        
        try {
            eval(code);
            executed++;
        } catch (e) {
            exceptions++;
        }
    }

    return { executed: executed, exceptions: exceptions };
};

var fuzzer = new fuzzer();
app.beep(0);
var stats = fuzzer.runFuzzLoop(990);
app.beep(0);
```
Heres a sample the fuzzer generated:
```js
(function() {
var v_2_3043 = (function() { var v_3_7308 = v_1_2415;
try { (v_1_2415).__proto__ = v_0_9759; } catch(e) {}
 return v_0_9759; })();
try { (v_3_7308).__proto__ = v_2_3043; } catch(e) {}
try { v_0_9759["prop_896"] = new Array(7); } catch(e) {}
})();
```

And here is the performance (beep 1 called before fuzzing and beep 2 after):

<img width="513" height="61" alt="image" src="https://github.com/user-attachments/assets/d2d38be4-f4bc-4e87-9b3a-d1884460fef6" />

990 iterations in 142 ms, ~7000 execs/s. Nice! 

You might be thinking "If my target crashses and I'm not passing samples individually but instead having the script generate random samples, how do I recover the interesting sample?" My solution was to use a seeded random number generator. That way, if a script crashes, I can get the latest seed, generate all the samples that would be generated with that seed, then feed each sample individually to the engine.

## What now?

Currently, these are the approaches I'm trying to take advantage with this method:
1. Completely Dumb Self-Fuzzing (as shown above)
2. Guided Self-Fuzzing
3. Shared Memory Delivery by String Body

### Completely Dumb Fuzzing
As described above. Pick an API exposed to your engine and leave your computer on.

### Coverage-Guided Self-Fuzzing
Primary idea is to use coverage-guidance to identify strong base cases and use the runner script to change how the self-fuzzing script generates samples. They all generally would append some data (literally add a `var symbol_weights = [1,2,3,...]` to the top of the file) that would affect how the symbols are chosen during code generation (`chosen = pick_exp_rand(exps, symbol_weights)`). The three primary ways I've thought about is:
1. Using the coverage to guide weighted random expansions (evolutionary probabilistic grammar fuzzing)
    * Basically have `generate()` functions read from a weight table, where the runner script can append the weight table to the top of the script in the form of an array.
    * My intuition says that this could work but you might run into situations where you would want a choice to be weighted in a certain way if and only if a certain token/sequence proceeds it (kind of a like an LLM with token prediction (not an LLM expert, only what I've heard on Youtube))
    * Saw `EVOEvoGFuzz` abstract, seems pretty similar.
2. Representing expansion choices as a set of integers that are mutated
    * You could represent the random expansions as an array, ie. `[7, 4, 2, 3]` where 7 was the 7th expansion choice for the current symbol, 4 was the 4th expansion for that symbol, etc.
    * Similar problems, changing/inserting/deleting an number upstream would affect which symbol is picked later.
3. Tree mutation
    * If you could represent the sample as an AST, then your self-fuzzer could mutate the tree, kind of like Jackalope.
    * My target seems to have a hard limit on character size of the script and I haven't gotten around to this approach yet. I would have the runner script append the tree as a JSON object and also need to JS to mutate it and that doesn't seem like it would fit in the character limit (solution could be storing JS in a PDF field, getting the text, and then `eval()`ing it since I don't think fields have character limits)

### Shared Memory Delivery by String Body
Probably the holy grail of fuzzing delivery, we can get much deeper mutation/generation logic much faster by outsouring it to a engine written in C, C++, Rust, Go, etc. For this approach we can write something that looks like this:
```js
var arr = [0x11223344, "I'm going to be overwritten :("]
while(true) {
    app.beep(0) //some rarely called API to hook for synchronization/coverage

    eval(arr[1])

    app.beep(0)
}
```
In SpiderMonkey specifically, we can easily get a pointer to `arr[1]` by searching in memory for `0xfff8800011223344` as described [here](https://vigneshsrao.github.io/posts/play-with-spidermonkey/) and looking at the pointer right next to it. Then we can either overwrite that pointer with to a pointer a string object we allocate, overwrite it with a pointer to shared memory where the mutator can generate a JS string object for us, or edit the contents of the string itself.

For delivery, we can hook `beep` to signal the external fuzzing engine to generate a sample, write it to shared memory, and start gathering coverage, then `beep` again to stop gathering coverage.

#### Caveats
The heap will be polluted and is not reset every iteration, which could lead to bugs that were not caused by a single sample, but maybe multiple samples setting up the heap in a certain way. This approach ignores those bugs, since we want to focus on bugs that could be triggered from a single scope; once the sample is done running, the sample returns and all the variables go out of scope. This could be mitigated by finding a garbage collection function and calling it to clean up the heap.

## Final Thoughts
I think fuzzing is really cool since the only way to get results is by doing things that other people are not, which leads to me thinking really creatively about problems. Also I get to work on grammars, languages, and automated code gen, which I think all are awesome.
