CXXFLAGS = -Wall -Wunused

default:
	$(CXX) $(CXXFLAGS) -Ilibpamc/include -Ilibpam_misc/include -lpam -lpam_misc login.c -o login

tags:
	ctags --recurse=yes --exclude=.git

.PHONY: tags
