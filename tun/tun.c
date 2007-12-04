#include "ruby.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>

VALUE tun_alloc(VALUE self, VALUE fd)
{
	struct ifreq ifr;
	char dev[10];
	int filedes = NUM2INT(fd);

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_NO_PI;
	ifr.ifr_flags |= IFF_TUN;

	if (ioctl(filedes, TUNSETIFF, &ifr) == -1)
	{
		perror("TUNSETIFF");
		exit(1);
	}

	strcpy(dev, ifr.ifr_name);

	return rb_str_new2(dev);
}

VALUE setiff(VALUE self)
{
  printf("%x\n",TUNSETIFF);
	return INT2FIX(TUNSETIFF);
}

VALUE ifr(VALUE self)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_NO_PI;
	ifr.ifr_flags |= IFF_TUN;
	return rb_str_new(&ifr, sizeof(ifr));
}

void Init_tun()
{
	VALUE rb_mTun = rb_define_module("Tun");

	rb_define_module_function(rb_mTun, "alloc", tun_alloc, 1);
	rb_define_module_function(rb_mTun, "setiff", setiff, 0);
	rb_define_module_function(rb_mTun, "ifr", ifr, 0);
}
