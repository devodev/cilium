# Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Isovalent Inc and its suppliers, if any. The intellectual and technical
# concepts contained herein are proprietary to Isovalent Inc and its suppliers
# and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.  Dissemination of this information
# or reproduction of this material is strictly forbidden unless prior written
# permission is obtained from Isovalent Inc.

include ../../cilium-dbg/Makefile

# Override the upstream `install-binary` 
# Using `ln -fns cilium-dbg <link>` creates a relative symlink
# that works with both busybox (chainguard) and whatever is used in oss images.
install-binary:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
	$(QUIET)ln -fns $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET_OLD)

install-bash-completion-only:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(CONFDIR)/bash_completion.d
	./$(TARGET) completion bash > $(TARGET)_bash_completion
	$(QUIET)$(INSTALL) -m 0644 $(TARGET)_bash_completion $(DESTDIR)$(CONFDIR)/bash_completion.d/$(TARGET)
