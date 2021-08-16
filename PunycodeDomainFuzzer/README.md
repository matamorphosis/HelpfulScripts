This is a library that is a replica of the [Scrummage](https://github.com/matamorphosis/Scrummage) project's [Rotor.py](https://github.com/matamorphosis/Scrummage/blob/master/app/plugins/common/Rotor.py) library. The implementation in Scrummage cannot be easily used outside of the project due to the framework it is embedded in. So this script was created as an independent version. It needs to be used as a python library, not as a CLI script.

This library work by supplying it with the body of a domain (bing.com -> bing). The user needs to set one or more flags. The flags are listed below, each is a boolean that is set to `False` by default:
- English_Upper=False (Include English Uppercase characters)
- Numbers=False (Include Numbers in the iteration)
- Special_Characters=False (Include Special Characters in the iteration)
- Asian=False (Use characters from various asian alphabets)
- Latin=False (Use characters from various latin alphabets)
- Middle_Eastern=False (Use characters from various middle-eastern alphabets)
- Native_American=False (Use characters from various native-american alphabets)
- North_African=False (Use characters from various north-african alphabets)
- Latin_Alternatives=False (Use characters from non-European languages using the latin alphabet (Such as Vietnamese characters))
- Comprehensive=False (Uses a more comprehensive list of characters, can only be used with Latin)

For a write-up on the various types of options, refer to the `Domain Fuzzer - Punycode` section [here](https://github.com/matamorphosis/Scrummage/wiki/The-Long-List-of-Tasks#domain-fuzzer).

**Example of Usage**
![Example](images/import.png)