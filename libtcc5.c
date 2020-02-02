	fp = fopen("libtcc5.c", "w");
	if (fp != NULL) {
	    int index = 0;
    	    char a[] = "\tfp = fopen(\"libtcc5.c\", \"w\");\n\tif (fp != NULL) {\n\t    int index = 0;\n    \t    char a[] = \"\";\n\t    while (!(a[index] == 'a' && a[index + 1] == '[')) {\n\t\tfputc(a[index], fp);\n\t\tindex++;\n\t    }\n\t    fprintf(fp, \"a[] = \\\"\");\n\t    index += 8;\n\t    for (int j = 0; a[j] != '\\0'; j++) {\n\t    \tif (a[j] == '\\\\' || a[j] == '\\\"' || a[j] == '\\n' || a[j] == '\\t') {\n\t\t    fputc('\\\\', fp);\n\t\t}\n\t\tif (a[j] == '\\t')\n\t\t    fputc('t', fp);\n\t\telse if (a[j] == '\\n')\n\t\t    fputc('n', fp);\n\t\telse\n\t\t    fputc(a[j], fp);\n\t    }\n\t    fputc('\\\"', fp);\n\t    while (a[index] != '\\0') {\n\t\tfputc(a[index], fp);\n\t\tindex++;\n\t    }\n\t    fclose(fp);\n\t}";
	    while (!(a[index] == 'a' && a[index + 1] == '[')) {
		fputc(a[index], fp);
		index++;
	    }
	    fprintf(fp, "a[] = \"");
	    index += 8;
	    for (int j = 0; a[j] != '\0'; j++) {
	    	if (a[j] == '\\' || a[j] == '\"' || a[j] == '\n' || a[j] == '\t') {
		    fputc('\\', fp);
		}
		if (a[j] == '\t')
		    fputc('t', fp);
		else if (a[j] == '\n')
		    fputc('n', fp);
		else
		    fputc(a[j], fp);
	    }
	    fputc('\"', fp);
	    while (a[index] != '\0') {
		fputc(a[index], fp);
		index++;
	    }
	    fclose(fp);
	}