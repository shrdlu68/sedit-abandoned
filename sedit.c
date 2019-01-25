#define _XOPEN_SOURCE 500
#define _POSIX_C_SOURCE 200112L
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <newt.h>
#include <selinux/selinux.h>
#include <sys/types.h>
#include <pwd.h>
#include <dirent.h>

#include <semanage/seuser_record.h>
#include <semanage/seusers_policy.h>
#include <semanage/seusers_local.h>

#define PERMISSIVE 0
#define ENFORCING 1

/* Screen dimensions */
int cols, rows;

/* Calculate center position based on width */
int center_left (int width)
{
  return (rows - width) / 2;
}

void dump(char *str, int n){
  printf("-->");
  for (int index=0; index<n; index++)
    putchar(str[index]);
  printf("<--\n");
}

/* Make table with neat rows */
char ** make_table(int rows, int columns, char **titles, char ***entries)
{
  /* Calculate width of widest entry per column */
  int widest_entry[columns], widest_entry_tmp[columns];
  memset(widest_entry, 0, columns*sizeof(unsigned int));
  memset(widest_entry_tmp, 0, columns*sizeof(unsigned int));
  for (int index=0; index<columns; index++){
    widest_entry[index] = strlen(titles[index]);
    for (int row_index=0; row_index<rows; row_index++){
      widest_entry_tmp[index] = strlen(entries[row_index][index]);
      if (widest_entry_tmp[index]>widest_entry[index])
	widest_entry[index] = widest_entry_tmp[index];
    }
  }
  /* Calculate the widest width */
  int widest_width = columns;
  for (int index=0; index<columns; index++) widest_width+=widest_entry[index];
  /* Allocate */
  char **out = calloc(rows+1, sizeof(char *));
  for (int index=0; index<rows+1; index++)
    out[index] = calloc(widest_width, sizeof(char));
  /* Format */
  char **row;
  /* Title */
  for (int column_index=0, print_pos=0;
       column_index<columns;
       column_index++, print_pos+=(widest_entry[column_index-1]+1))
    sprintf(&(out[0][print_pos]),
	    column_index<columns-1 ? "%-*s " : "%-*s",
	    widest_entry[column_index], titles[column_index]);
  for (int index=0; index<rows; index++){
    row = entries[index];
    for (int column_index=0, print_pos=0;
	 column_index<columns;
	 column_index++, print_pos+=(widest_entry[column_index-1]+1)){
      sprintf(&(out[index+1][print_pos]),
	      column_index<columns-1 ? "%-*s " : "%-*s",
	      widest_entry[column_index], row[column_index]);
    }
  }
  return out;
}

bool yes_no (const char *question){
  newtCenteredWindow(cols/4, rows/3, question);
  newtComponent fm = newtForm(NULL, NULL, NEWT_FLAG_NOF12);
  newtComponent yes_button = newtButton(2, 10, "Yes");
  newtComponent no_button = newtButton(cols/4-10, 10, "No");
  newtFormAddComponent(fm, yes_button);
  newtFormAddComponent(fm, no_button);
  struct newtExitStruct es;
  newtFormRun(fm, &es);
  /* Since we didn't define any hotkey, es.reason will always be NEWT_EXIT_COMPONENT */
  bool res = false;
  if (es.u.co == yes_button) res = true;
  newtFormDestroy(fm);
  newtPopWindow();
  return res;
}

void alert_error (const char *msg){
  newtCenteredWindow(cols/3, rows/4, "Error");
  newtComponent fm = newtForm(NULL, NULL, NEWT_FLAG_NOF12);
  newtComponent textbox = newtTextbox(2, 2, strlen(msg), 1, 0);
  newtTextboxSetText(textbox, msg);
  newtComponent exit_button = newtButton(2, 8, "Exit");
  newtFormAddComponents(fm, textbox, exit_button, NULL);
  newtRunForm(fm);
  newtFormDestroy(fm);
  newtPopWindow();
}

void matchp (const char *substr, char **str, int len, bool *bools){
  for (int index=0; index<len; index++)
    if (strstr(str[index], substr) != NULL) bools[index]=true; else bools[index]=false;
}

/* Copy Passwd struct */
struct passwd * copy_passwd (struct passwd Old)
{
  struct passwd *New = malloc(sizeof(struct passwd));
  /* Alloc and copy char *pw_name */
  New->pw_name = calloc(strlen(Old.pw_name)+1, sizeof(char));
  strcpy(New->pw_name, Old.pw_name);
  /* Alloc and copy char *pw_passwd */
  New->pw_passwd = calloc(strlen(Old.pw_passwd)+1, sizeof(char));
  strcpy(New->pw_passwd, Old.pw_passwd);
  /* Copy pw_uid and pw_gid */
  New->pw_uid = Old.pw_uid;
  New->pw_gid = Old.pw_gid;
  /* Alloc and copy char *pw_gecos */
  New->pw_gecos = calloc(strlen(Old.pw_gecos)+1, sizeof(char));
  strcpy(New->pw_gecos, Old.pw_gecos);
  /* Alloc and copy char *pw_dir */
  New->pw_dir = calloc(strlen(Old.pw_dir)+1, sizeof(char));
  strcpy(New->pw_dir, Old.pw_dir);  
  /* Alloc and copy char *pw_shell */
  New->pw_shell = calloc(strlen(Old.pw_shell)+1, sizeof(char));
  strcpy(New->pw_shell, Old.pw_shell);
  return New;
}

/* Copy dirent struct */
struct dirent * copy_dirent (struct dirent Old)
{
  struct dirent *New = malloc(sizeof(struct dirent));
  /* Copy d_ino */
  New->d_ino = Old.d_ino;
  /* Copy d_off */
  New->d_off = Old.d_off;
  /* Copy d_reclen */
  New->d_reclen = Old.d_reclen;
  /* Copy d_type */
  New->d_type = Old.d_type;
  /* Copy d_name */
  strcpy(New->d_name, Old.d_name);
  return New;
}

/* Get all directory contents */
struct dirent * dir_contents(DIR *path, int *contents_len)
{
  struct dirent *contents;
  struct dirent *tmp;
  *contents_len = 0;
  int buf_len = 5;
  contents = calloc(buf_len, sizeof(struct dirent));
  do{
    if(*contents_len==buf_len){
      buf_len+=20;
      contents = realloc(contents, buf_len * sizeof(struct dirent));
    }
    tmp = readdir(path);
    if(tmp){
      contents[*contents_len] = *(copy_dirent(*tmp));
      /* printf("%d %s\n", *contents_len, (*contents)[*contents_len].d_name); */
      (*contents_len)++;
    }
  }while(tmp);
  contents = realloc(contents, *contents_len * sizeof(struct dirent));
}

void filesystem()
{
  /* Create window */
  newtCenteredWindow(cols/2, rows/2, "SEdit > filesystem");
  newtPushHelpLine("<Esc>Back");
 
  /* Form that holds everything */
  newtComponent fm = newtForm(NULL, NULL, 0);
  /* EntryBox for directory */
  const char *path_str;
  newtComponent path_label = newtLabel(center_left(strlen("Path:")), 1, "Path:");
  newtComponent path = newtEntry(center_left(40), 2, NULL, 40, &path_str, 0);
  newtFormSetHeight(fm, (rows/2)-1);
  newtFormAddComponents(fm, path, path_label);
  /* Filter box for contents */
  const char *filter_str;
  newtComponent filter_label = newtLabel(center_left(strlen("Filter:")), 1, "Filter:");
  newtComponent filter = newtEntry(center_left(40), 4, NULL, 40, &filter_str, 0);
  newtFormSetHeight(fm, (rows/2)-1);
  newtFormAddComponents(fm, filter, filter_label);
  /* List contents, default to / */
  DIR *default_directory = opendir("/");
  int contents_len = 0;
  /* Get directory contents */
  struct dirent *contents = dir_contents(default_directory, &contents_len);
  /* Get selinux context for each of the dir entries */
  char *con[contents_len];
  int getfilecon_ret[contents_len];
  
  for (int index=0; index<contents_len; index++){
    getfilecon_ret[index] = getfilecon(contents[index].d_name, &con[index]);
    /* printf("%d<---->%s\n", getfilecon_ret[index], con[index]); */
  }
  /* Format output string */
  char ***c_rows = calloc(contents_len, sizeof(char **));
  for (int index=0; index<contents_len; index++){
    c_rows[index] = calloc(2, sizeof(char *));
    c_rows[index][0] = contents[index].d_name;
    c_rows[index][1] = getfilecon_ret[index] == -1 ? "Error" : con[index];
  }
  char *titles[] = {"Path", "Security Context"};
  char **output = make_table(contents_len, 2, titles, c_rows);
  /* Create label for title */
  newtComponent title_label = newtLabel(2, 7, output[0]);
  newtFormAddComponent(fm, title_label);
  /* Create  listbox */
  newtComponent list_box = newtListbox(2, 8, (rows/2)-9, NEWT_FLAG_RETURNEXIT | NEWT_FLAG_SCROLL);
  newtFormAddComponent(fm, list_box);
  for (int index=1; index<contents_len+1; index++)
    newtListboxAppendEntry(list_box, output[index], output[index]);
  newtFormRun(fm, NULL);
}

/* Get all usernames */
void get_users(struct passwd **users, int *users_len)
{
  *users_len = 0;
  int buf_len = 5;
  *users = calloc(buf_len, sizeof **users);
  struct passwd *P;
  do{
    if(*users_len==buf_len){
      buf_len+=20;
      *users = realloc(*users, buf_len * sizeof **users);
    }
    P = getpwent();
    if(P!=NULL){
      (*users)[*users_len] = *(copy_passwd(*P));
      /* printf("%d %s\n", *users_len, (*users)[*users_len].pw_name); */
      (*users_len)++;
    }
  }while(P);
  *users = realloc(*users, *users_len * sizeof **users);
  endpwent();
}

void modify_user_context(char *username, const char *se_role, const char *se_level){
  
}

void edit_user(char *username){
  /* Create window */
  char title[strlen("Modify SELinux user/level for user: ")+strlen(username)+1];
  sprintf(title, "Modify SELinux user/level for user: %s", username);
  newtCenteredWindow(cols/2, 10, title);
  newtPushHelpLine("<Esc>Back to list of users");
  newtComponent fm = newtForm(NULL, NULL, NEWT_FLAG_NOF12);
  newtFormAddHotKey(fm, NEWT_KEY_ESCAPE);
  newtComponent seuser_label = newtLabel(2, 2, "SELinux User:");
  newtComponent selevel_label = newtLabel(2, 4, "Security level:");
  const char *se_user;
  const char *se_level;
  const char *initial_user, *initial_level;
  getseuserbyname(username, (char **) &initial_user, (char **) &initial_level);
  newtComponent se_user_entry = newtEntry(18 , 2, initial_user, 40, &se_user, 0);
  newtComponent se_level_entry = newtEntry(18 , 4, initial_level, 40, &se_level, 0);
  newtComponent save_button = newtButton(30, 6, "Save");
  newtFormAddComponents(fm, seuser_label, selevel_label, se_user_entry, se_level_entry, save_button, NULL);
  struct newtExitStruct es;
  newtFormRun(fm, &es);
  if(es.reason == NEWT_EXIT_COMPONENT) modify_user_context(username, se_user, se_level);
  newtFormDestroy(fm);
  newtPopWindow();
}

/* Display user mappings and roles */
void display_users (char **output, char **users, int len, bool *visible){
  /* Create window */
  newtCenteredWindow(cols/2, rows/2, "SEdit > users");
  newtPushHelpLine("<Esc>Back"); 
  /* Form that holds everything */
  newtComponent fm = newtForm(NULL, NULL, 0);
  newtFormAddHotKey(fm, NEWT_KEY_ESCAPE);
  /* EntryBox for filtering */
  const char *filter_str;
  newtComponent filter_label = newtLabel(center_left(strlen("Search users:")), 1, "Search users:");
  newtComponent filter = newtEntry(center_left(40), 2, NULL, 40, &filter_str, NEWT_FLAG_RETURNEXIT);
  newtFormSetHeight(fm, (rows/2)-1);
  newtFormAddComponent(fm, filter_label);
  newtFormAddComponent(fm, filter);
  /* Title */
  newtComponent title_co = newtLabel(2, 3, output[0]);
  newtFormAddComponent(fm, title_co);
  /* Create Listbox */
  newtComponent list_box = newtListbox(2, 4, (rows/2)-5, NEWT_FLAG_SCROLL | NEWT_FLAG_RETURNEXIT);
  newtFormAddComponent(fm, list_box);
  for (int index=1; index<len+1; index++)
    if(visible[index-1]) newtListboxAppendEntry(list_box, output[index], users[index-1]);
  struct newtExitStruct es;
  newtFormRun(fm, &es);
  /* Check exit reason */
  if(es.reason == NEWT_EXIT_COMPONENT){
    if (es.u.co == filter){
      matchp(filter_str, users, len, visible);
    }else{
      edit_user(newtListboxGetCurrent(list_box));
    }
    newtFormDestroy(fm);
    newtPopWindow();
    display_users(output, users, len, visible);
  }else{
    newtFormDestroy(fm);
    newtPopWindow();
  }
}

void users()
{
  /* Get list of users */
  struct passwd *users;
  int users_len;
  get_users(&users, &users_len);
  /* Get SELinux name for each user */
  char *selinuxuser[users_len];
  char *selinuxlevel[users_len];
  for (int index=0; index<users_len; index++){
    getseuserbyname(users[index].pw_name, &selinuxuser[index], &selinuxlevel[index]);
  }
  /* Format */
  char ***c_rows = calloc(users_len+1, sizeof(char **));
  for (int index=0; index<users_len; index++){
    c_rows[index] = calloc(3, sizeof(char *));
    c_rows[index][0] = users[index].pw_name;
    c_rows[index][1] = selinuxuser[index];
    c_rows[index][2] = selinuxlevel[index];
  }
  char *titles[] = {"Username", "SELinux User", "Security level"};
  char **output = make_table(users_len, 3, titles, c_rows);
  bool visible[users_len];
  for (int index=0; index<users_len; index++) visible[index]=true;
  char *usernames[users_len];
  for (int index=0; index<users_len; index++) usernames[index]=users[index].pw_name;
  display_users(output, usernames, users_len, visible);
}

void display_booleans (char **booleans, int len, bool *visible){
  /* Create window */
  newtCenteredWindow(cols/2, rows/2, "SEdit > booleans");
  newtPushHelpLine("<Esc>Back");
 
  /* Form that holds everything */
  newtComponent scroll_bar = newtVerticalScrollbar(cols/2, 2, (rows/2)-2,
						   NEWT_COLORSET_WINDOW,
						   NEWT_COLORSET_ACTCHECKBOX);
  newtComponent fm = newtForm(scroll_bar, NULL, NEWT_FLAG_NOF12);
  newtFormAddHotKey(fm, NEWT_KEY_ESCAPE);
  /* Build list of checkboxes */
  newtComponent boolean_checkboxes[len];
  int top = 4;
  for (int index=0; index<len; index++){
    if (visible[index]){
      boolean_checkboxes[index] = newtCheckbox(2, top++, booleans[index],
					       security_get_boolean_active(booleans[index]) == 1 ? '*' : ' ',
					       "* ", NULL);
      newtFormAddComponent(fm, boolean_checkboxes[index]);
    }
  }
  /* EntryBox for filtering */
  const char *filter_str;
  newtComponent filter_label = newtLabel(center_left(strlen("Filter booleans:")), 1, "Filter booleans:");
  newtComponent filter = newtEntry(center_left(40), 2, NULL, 40, &filter_str, NEWT_FLAG_RETURNEXIT);
  newtFormSetHeight(fm, (rows/2)-1);
  newtFormAddComponents(fm, filter_label, filter, scroll_bar, NULL);
  newtFormSetCurrent(fm, filter);
  struct newtExitStruct es;
  newtFormRun(fm, &es);
  /* Check if reason for exiting was the entrybox, which is the only component that can exit */
  if(es.reason == NEWT_EXIT_COMPONENT){
    matchp(filter_str, booleans, len, visible);
    newtFormDestroy(fm);
    newtPopWindow();
    display_booleans(booleans, len, visible);
  }else{
    /* Check whether any of the booleans changed */
    bool booleans_changed = false;
    for (int index=0; index<len; index++){
      if(visible[index]!=true) continue;
      if(newtCheckboxGetValue(boolean_checkboxes[index]) == ' ' && security_get_boolean_active(booleans[index]) == 1) booleans_changed=true;
      if(newtCheckboxGetValue(boolean_checkboxes[index]) == '*' && security_get_boolean_active(booleans[index]) == 0) booleans_changed=true;
    }
    /* Ask to save changes */
    if(booleans_changed && yes_no("Save changes to booleans?")){
      SELboolean boollist[len];
      for (int index=0; index<len; index++){
	boollist[index].name = booleans[index];
	if(visible[index]){
	  boollist[index].value = newtCheckboxGetValue(boolean_checkboxes[index]) == '*' ? 1 : 0;
	}else{
	  boollist[index].value = security_get_boolean_active(booleans[index]);
	}
      }
      int res = security_set_boolean_list(len, boollist, 1);
      if(res == -1){
	alert_error("Failed to save changes. Are you authorized to?");
      }
    }
    newtFormDestroy(fm);
    newtPopWindow();
  }
}

void booleans()
{
  /* Get list of booleans */
  char **booleans;
  int booleans_len;
  security_get_boolean_names(&booleans, &booleans_len);
  bool visible[booleans_len];
  for (int index=0; index<booleans_len; index++) visible[index]=true;
  display_booleans(booleans, booleans_len, visible);
}

void start_window (){
  /* Create window */
  newtCenteredWindow(cols/2, rows/2, "SEdit > status");
  newtPushHelpLine("<Esc>Exit	<b>Booleans	<f>Filesystem	<u>Users	<p>Processes	<n>Network ports	<m>Policy modules");

  /* Create Newt form */
  newtComponent fm;
  fm = newtForm(NULL, NULL, 0);
  newtFormAddHotKey(fm, NEWT_KEY_ESCAPE);
  newtFormAddHotKey(fm, 'b');
  newtFormAddHotKey(fm, 'f');
  newtFormAddHotKey(fm, 'u');
  newtFormAddHotKey(fm, 'p');
  newtFormAddHotKey(fm, 'n');
  newtFormAddHotKey(fm, 'm');

  /* Is SELinux enabled */
  int run_status = is_selinux_enabled();
  if(run_status==1){
    
    /* Query Enforcing mode */
    int enforce_mode = security_getenforce();
    newtComponent mode_label = newtLabel(0, 2, "Mode:");
    newtFormAddComponent(fm, mode_label);
    newtComponent mode_rb[2];
    mode_rb[0] = newtRadiobutton(2, 3, "Enforcing", enforce_mode, NULL);
    mode_rb[1] = newtRadiobutton(2, 4, "Permissive", enforce_mode==1 ? 0 : 1, mode_rb[0]);
    int i;
    for (i = 0; i < 2; i++) newtFormAddComponent(fm, mode_rb[i]);

    /* Query MLS */
    int mls_p = is_selinux_mls_enabled();
    newtComponent mls_label = newtLabel(0, 6, "MLS-capable:");
    newtFormAddComponent(fm, mls_label);
    newtComponent mls_rb[2];
    mls_rb[0] = newtRadiobutton(2, 7, "Yes", mls_p, NULL);
    mls_rb[1] = newtRadiobutton(2, 8, "No", mls_p==1 ? 0 : 1, mls_rb[0]);
    for (i = 0; i < 2; i++) newtFormAddComponent(fm, mls_rb[i]);

    /* Query Policy type */
    char *policy_type;
    selinux_getpolicytype(&policy_type);
    newtComponent policy_label = newtLabel(0, 10, "Policy:");
    newtFormAddComponent(fm, policy_label);
    int targeted_p = strcmp("targeted", policy_type);
    newtComponent policy_rb[2];
    policy_rb[0] = newtRadiobutton(2, 11, "Targeted", targeted_p==0 ? 1 : 0, NULL);
    policy_rb[1] = newtRadiobutton(2, 12, "MLS", targeted_p!=0 ? 1 : 0, policy_rb[0]);
    for (i = 0; i < 2; i++) newtFormAddComponent(fm, policy_rb[i]);

    struct newtExitStruct fm_ret;
    newtFormRun(fm, &fm_ret);
    free(policy_type);

    bool exit = false;

    switch (fm_ret.u.key){
    case NEWT_KEY_ESCAPE:
      exit=true;
      break;
    case 'b':
      booleans();
      break;
    case 'u':
      users();
      break;
    case 'f':
      filesystem();
      break;
    }
    newtFormDestroy(fm);
    newtPopWindow();
    if(exit == false) start_window();
  }else if(run_status==0){
    newtDrawRootText(0, 10, "SELinux is disabled");
  }else{
    newtDrawRootText(0, 10, "Error querying SELinux status");
  }
  newtFormDestroy(fm);
  newtPopWindow();
}

int main (int argc, char **argv)
{
  /* Set preferred colors */
  setenv("NEWT_COLORS", "checkbox=black,white", 0);
  
  /* Initialize Newt */
  newtInit();
  newtCls();

  /* Get screen size */
  newtGetScreenSize(&cols, &rows);
  start_window();
  newtFinished();
  return 0;
}
