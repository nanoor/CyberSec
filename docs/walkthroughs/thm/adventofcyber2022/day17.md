---
title: Day 17 - Secure Coding (Regular Expressions)
desc: >-
  Day 17 covers topics regarding input sanitation and use of regular expressions
  in input validation.
---
## Regex Fundamentals

- The `[ ]` indicate that you're trying to match one character within the set of characters inside of them. For example, if we're trying to match any vowel of the English alphabet, we construct our regex as follows: `[aeiou]`. The order of the characters doesn't matter, and it will match the same.
- You can also mix and match sets of characters within the bracket. `[a-zA-Z]` means you want to match any character from the English alphabet regardless of case, while `[a-z0-9]` means you want to match any lowercase alphanumeric character.
- The wildcard operator is denoted by `.`.
- The `*` operator is used if you don't care if the preceding token matches anything or not.
- The `+` operator is used if you want to make sure the preceding token matches at least once. For example, to match a string that is alphanumeric and case insensitive, our pattern would be `[a-zA-Z0-9]+`. The `+` operator means that we want to match a string . We don't care how long it is, as long as it's composed of letters and numbers regardless of their case.
- The `^` and `$` operators are called anchors and denote the start and end of the string we want to match, respectively. If we want to ensure that the start of a string is composed of only letters, adding the caret operator is required. For example, if we want to ensure that the first part of the string is composed of letters and we want it to match regardless if there are numbers thereafter, the expression would be `^[a-zA-Z]+[0-9]*$`.
- The `{min,max}` operator specifies the number of characters you want to match. For example, if we want to match just lowercase letters that are in between 3 and 9 characters in length, our pattern would be `^[a-z]{3,9}$`. If we want a string that starts with 3 letters followed by any 3 characters, our pattern would be `^[a-zA-Z]{3}.{3}$`.
- Grouping is denoted by the `( )`. Grouping is typically done to manage the matching of specific parts of the regex better.
- Escaping is denoted by `\`. Escaping is used so we can match strings that contain regex operators.
- The `?` operator denotes that the preceding token is optional.

Following is a table with summarizes the information presented above.

| Operator                                                  | Function                                                                                |
|:---------------------------------------------------------:|:--------------------------------------------------------------------------------------- |
| [ ]                                                       | Character Set: matches any single character/range of characters inside                  |
| .                                                         | Wildcard: matches any character                                                         |
| *                                                         | Star/Astrix Quantifier: matches the preceding token zero or more times                  |
| +                                                         | Plus Quantifier: matches the preceding token one or more times                          |
| {min,max}                                                 | Curly Brace Quantifier: specifies how many times the preceding token can be repeated    |
| ( )                                                       | Grouping: groups a specific part of the regex for better management                     |
| \|Escape: escapes the regex operator so it can be matched |                                                                                         |
| ?                                                         | Optional: specifies that the preceding token is optional                                |
| ^                                                         | Anchor Beginning: specifies that the consequent token is at the beginning of the string |
| $                                                         | Anchor Ending: specifies that hte preceding token is at the end of the string           |

### CTF Questions

1. Use `egrep '^[a-zA-Z0-9]{6,12}$' strings`
2. Use `egrep '^[a-zA-Z]+[0-9]{1}+$' strings`
3. Use `egrep '^.+@.+\.com$' strings`
4. Simply count the unique domains listed in `3`
5. Use `egrep '^lewisham44@.+\.com$' strings`
6. Use `egrep '^maxximax@.+\.com$' strings`
7. Use `egrep '^.+@hotmail\.com$' strings`
8. Use `egrep '^http(s)?(://)(www\.)?.+\..$' strings`
9. Use `egrep '^https://(www\.)?.+\..$' strings`