# Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Isovalent Inc and its suppliers, if any. The intellectual and technical
# concepts contained herein are proprietary to Isovalent Inc and its suppliers
# and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.  Dissemination of this information
# or reproduction of this material is strictly forbidden unless prior written
# permission is obtained from Isovalent Inc.

include ../../hubble/Makefile

.PHONY: install-bash-completion
install-bash-completion: $(TARGET)
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(CONFDIR)/bash_completion.d
	./$(TARGET) completion bash > $(TARGET)_bash_completion
	$(QUIET)$(INSTALL) -m 0644 $(TARGET)_bash_completion $(DESTDIR)$(CONFDIR)/bash_completion.d/$(TARGET)
