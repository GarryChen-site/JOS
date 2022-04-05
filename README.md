
* lab3

for GCC7 or later,you need to modify kern/kernel.ld

```text
    .bss : {
		PROVIDE(edata = .);
		*(.bss)
		*(COMMON)  // add
		PROVIDE(end = .);
		BYTE(0)
	}
```