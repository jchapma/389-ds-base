/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc. Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/
/*
 * index.c: Shows the first page you see on install
 * 
 * Rob McCool
 */

#include <nss.h>
#include <libadminutil/distadm.h>

#include "create_instance.h"
#include "configure_instance.h"

#include "dsalib.h"
#include "ldap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --------------------------------- main --------------------------------- */

static void
printInfo(int argc, char *argv[], char *envp[], FILE* fp)
{
	int ii = 0;
	if (!fp)
		fp = stdout;

	fprintf(fp, "Program name = %s\n", argv[0]);
	for (ii = 1; ii < argc; ++ii)
	{
		fprintf(fp, "argv[%d] = %s\n", ii, argv[ii]);
	}

	for (ii = 0; envp[ii]; ++ii)
	{
		fprintf(fp, "%s\n", envp[ii]);
	}

	fprintf(fp, "#####################################\n");
}

int main(int argc, char *argv[], char * /*envp*/ [])
{
    char *rm = getenv("REQUEST_METHOD");
    int status = 0;
    server_config_s cf;
	char *infFileName = 0;
	int reconfig = 0;
	int ii = 0;
	int cgi = 0;

	(void)ADMUTIL_Init();
	
	/* Initialize NSS to make ds_salted_sha1_pw_enc() happy */
	if (NSS_NoDB_Init(NULL) != SECSuccess) {
		ds_report_error(DS_GENERAL_FAILURE, " initialization failure",
				"Unable to initialize the NSS subcomponent.");
		exit(1);
	}

	/* make stdout unbuffered */
	setbuf(stdout, 0);

#ifdef XP_WIN32
    if ( getenv("DEBUG_DSINST") )
	DebugBreak();
#endif

    memset(&cf, 0, sizeof(cf));
    set_defaults(0, 0, &cf);

	/* scan cmd line arguments */
	for (ii = 0; ii < argc; ++ii)
	{
		if (!strcmp(argv[ii], "-f") && (ii + 1) < argc &&
			argv[ii+1])
			infFileName = argv[ii+1];
		else if (!strcmp(argv[ii], "-r"))
			reconfig = 1;
	}

    /* case 1: being called as program -f inffile */
    if (infFileName)
    {
		FILE *infFile = fopen(infFileName, "r");
		if (!infFile)
		{
			ds_report_error(DS_INCORRECT_USAGE, infFileName,
				"This file could not be opened.  A valid file must be given.");
			status = 1;
		}
		else
			fclose(infFile);

		if (reconfig)
			status = reconfigure_instance(argc, argv);
		else
		{
			if (!status)
				status = create_config_from_inf(&cf, argc, argv);
			if (!status)
				status = create_config(&cf);
			if (!status)
				status = configure_instance();
		}
    }
    /* case 2: being called as a CGI */
    else if (rm)
    {
		cgi = 1;
        status = parse_form(&cf);
		if (!status)
			status = create_config(&cf);
		if (!status)
			status = configure_instance_with_config(&cf, 1, 0);
    }
    /* case 3: punt */
    else
    {
		ds_report_error (
			DS_INCORRECT_USAGE,
			"No request method specified",
			"A REQUEST_METHOD must be specified (POST, GET) to run this CGI program.");
		status = 1;
    }

	if (cgi)
	{
		/* The line below is used by the console to detect
		   the end of the operation. See replyHandler() in
		   MigrateCreate.java */
		fprintf(stdout, "NMC_Status: %d\n", status);
		/* In the past, we used to call rpt_success() or rpt_err() 
		   according to status. However these functions are not designed
		   for our case: they print an HTTP header line "Content-type: text/html" */
	}

#if defined( hpux )
    _exit(status);
#endif
    return status;
}
