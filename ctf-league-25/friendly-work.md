# CTF League - Friendly Work

## Flag 1
The first flag would be printed at the start of the program if the user we create was an admin.
```c
  if (user->type == ADMIN) {
    print_flag(FLAG_1);
    printf("\n\n");
  }
```
Thee was no standard execution path that would set the user to admin priveledges, but we could circumvent this with a simple buffer overflow. When the program was run, it calls into a function `get_user()` to get user information, which among other things writes 32 bytes from stdin to a 24 byte struct field. Those additional bytes would be written to the subsequent struct fields, first of which is `user->type`     
```c
printf("Name: ");
read_input(user->name, 32);

typedef struct __attribute__((__packed__)) User {
  int32_t skill;
  char name[24];
  char type;
  char title[8];
} User;

const char NORMAL = 0;
const char TESTER = 1;
const char ADMIN = 78;
```
Admin priveledges would be granted to our user if the `user->type` field held the value 78. The value 78 is represents by the ASCII character N, so by filling the name buffer with N, we are granted admin priveledges, and the program prints out flag1. 
```
Title: 
Name: NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
Special user login (blank for nothing):

Hello
ADMIN  NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN

osu_flag1.txt
```

## Flag 2
The second flag is printed if we modify the work struct such that the field `work.friend = "XP"`. The value of `work.friend` is initialized to `":)"` and is never accessed or written to, so we need to attack an arbitrary write somewhere else in the program. 
```c
typedef struct __attribute__((__packed__)) Work {
  int32_t numbers_count;
  char friend[4];
  int32_t numbers[8];
  char message[64];
} Work;
```
Investigating the `work` struct, it is located on the stack, and we have the ability to write to the `work->numbers` array. Based on the stack layout, indexing `numbers[-1]` is equivalent to `numbers + (-1*(sizeof(int32_t)))`. The size of an int32_t is 4 bytes, which is identical to the size of `char friend[4]`. With packed struct, this means that `numbers[-1]` brings us to the starting address of `friend`. By using the "remove a number" option in the menu, we can write to `numbers[-1]`, subsequently writing to `friend`

We need friend to store the characters "XP", in a way that aligns with `friend[0]` and `friend[1]` so we can't simply input the string "XP" but instead pack the value like the following.
```python
ord('X') + (ord('P') * 256)
>>> 20568
```
With this value found, we can use the remove number option until we are accessing index -1, then use the add a number option with 20568, and finally using the option to check on a friend will print the flag.

```
He's doing okay right?
You killed him! The ultimate red osu_flag2.txt.
```
## Flag 3
The final flag would be written to the `work->message` field, if we requested it via, but simulated access control prevented printing the message when it contained the flag. 
```c
if (strcmp(work.message, "flag please ... PLEASE") == 0) {
        printf("Fine.\n\n");
        read_file(FLAG_3, work.message, 64); 
```
However, a side channel existed in the work friends methods, which would print the friend memory from the friend char array until it found a null byte
```c
if (work.friend[0] == ':' && work.friend[1] == ')') {
        printf("Yes he is right here: %s\n\n", work.friend);
```

Using the same vulnerability as flag 2, we needed to keep the ":)" intact, but remove the null byte, we used `344944814394 = ":)PPP"`. This number was generated the same way as the previous flag. Critically it maintains the ":)", while overwriting the `\0`. At this point we tried using the check on friend method, but it didn't print as far as we needed. 

Since we hadn't used the add number function (other than the -1 index), the numbers array  still contained zero-d out memory which were interpreted as null bytes, by adding garbage numbers that overwrote the existing 0s in the numbers array, the print function would continue through all of the struct until it found the null byte in the `message` field, which included printing the final flag.

```
He's doing okay right?
Yes he is right here: :)PP�ߩ9�ߩ9�ߩ9�ߩ9�ߩ9�ߩ9�ߩ9�ߩ9osu_flag3.txt
```