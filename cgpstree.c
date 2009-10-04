/*
 * ============================================================================
 *
 *       Filename:  cgpstree.c
 *
 *    Description:  pstree like tools for cgroup
 *
 *        Version:  0.0.2
 *        Created:  09/14/2009 01:40:48 PM
 *       Revision:  0.0.1
 *       Compiler:  gcc
 *
 *         Author:  Naoya Kaneko (enukane@skyperpc.net),
 *        Company:  Softlab, University of Tsukuba
 *
 * ============================================================================
 */

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<sys/types.h>
#include<errno.h>
#include<pthread.h>
#include<libcgroup-internal.h>
#include<libcgroup.h>



struct controller_info {
        char *name;
        char *mount_point;
        struct group_info *group_head;
        struct controller_info *next;
};



struct group_info {
        char *name;
        int depth;
        struct task_info  *task_head;
        struct group_info *parent;
        struct group_info *child_head;
        struct group_info *prev;
        struct group_info *next;
};

struct task_info {
        char *proc_name;
        pid_t pid;
        struct task_info *next;
};

void
cgpstree_free_task_list(struct task_info *head)
{
        struct task_info *curr = head;
        struct task_info *next;

        while (curr) {
                next = curr->next;
                free(curr);
                if (!next)
                        return;
                curr = next;
        }
}

struct task_info
*cgpstree_get_task_list(struct cgroup_file_info info,
                        char *root_path,
                        char *ctrl) {
        void *task_handle;
        pid_t pid;
        char *rel_path = NULL;
        int error;
        int ret;

        struct task_info *tinfo_head = NULL;
        struct task_info *curr_tinfo = NULL;
        struct task_info *prev_tinfo = NULL;

        rel_path = info.full_path + strlen(root_path) -1;

        error = cgroup_get_task_begin(rel_path, ctrl, &task_handle, &pid);

        if (error && error != ECGEOF)
                return NULL;

        while (error != ECGEOF) {
                curr_tinfo = (struct task_info*)malloc(sizeof(struct task_info));

                if (!curr_tinfo)
                        goto out_error;

                if (!tinfo_head)
                        tinfo_head = curr_tinfo;
                else
                        prev_tinfo->next = curr_tinfo;

                /** main **/
                curr_tinfo->pid = pid;
                ret = cgroup_get_procname_from_procfs(pid, &(curr_tinfo->proc_name));

                if (ret == ECGROUPNOTEXIST)
                        goto out_error;
		if (ret == ECGOTHER) {
			free(curr_tinfo);
			curr_tinfo = prev_tinfo;
		}

		printf("ret = %d: ", ret);
		printf("%s\n", curr_tinfo->proc_name);

		curr_tinfo->next = NULL;

                error = cgroup_get_task_next(&task_handle, &pid);

                if (error && error != ECGEOF)
                        goto out_error;

                prev_tinfo = curr_tinfo;
        }

        cgroup_get_task_end(&task_handle);
        return tinfo_head;

out_error:
        cgpstree_free_task_list(tinfo_head);
        cgroup_get_task_end(&task_handle);
        return NULL;
}

void
cgpstree_rec_free_group_tree(struct group_info *current)
{
	if (!current)
		return;
        if (current->next)
                cgpstree_rec_free_group_tree(current->next);
        if (current->child_head)
                cgpstree_rec_free_group_tree(current->child_head);
        free(current);

        return;
}

void
cgpstree_free_group_tree(struct group_info *head)
{
        struct group_info *curr_ginfo;

        curr_ginfo = head;
        cgpstree_rec_free_group_tree(head);

        return;
}

struct group_info
*cgpstree_get_group_tree(struct cgroup_mount_point mount_info) {
        struct group_info *curr_ginfo = NULL;
        struct group_info *prev_ginfo = NULL;
        struct group_info *root_ginfo = NULL;

        int curr_depth= -1;
        int prev_depth= -1;
        struct cgroup_file_info info;
        void *tree_handle;
        int lvl;
        int ret = 0, error;
        char *root_path = NULL;

        error = cgroup_walk_tree_begin(mount_info.name,"/",0,
                                       &tree_handle, &info,&lvl);

        if (error && error != ECGEOF)
                return NULL;

        root_path = strdup(info.full_path);

        if (!root_path) {
                cgroup_walk_tree_end(&tree_handle);
                return NULL;
        }

        ret = cgroup_walk_tree_set_flags(&tree_handle,
                                         CGROUP_WALK_TYPE_PRE_DIR);

        if (ret) {
                cgroup_walk_tree_end(&tree_handle);
                goto out_error;
        }

        while (error != ECGEOF) {
                if (info.type == CGROUP_FILE_TYPE_DIR) {
                        curr_ginfo = (struct group_info*)malloc(sizeof(struct group_info));
			
			curr_ginfo->parent	= NULL;
			curr_ginfo->next  	= NULL;
			curr_ginfo->prev  	= NULL;
			curr_ginfo->child_head 	= NULL;

                        curr_ginfo->depth = info.depth;
                        curr_ginfo->name = strdup(info.path);

                        curr_ginfo->task_head = cgpstree_get_task_list(info,root_path,mount_info.name);

                        curr_depth = info.depth;

                        if (root_ginfo == NULL) {
                                free(curr_ginfo->name);
				curr_ginfo->name = strdup("/");
				root_ginfo = curr_ginfo;
                        } else if (prev_depth == curr_depth) {
                                prev_ginfo->next = curr_ginfo;
                                curr_ginfo->prev = prev_ginfo;
                                curr_ginfo->parent = prev_ginfo->parent;
                        } else if ((prev_depth + 1) == curr_depth) {
                                prev_ginfo->child_head = curr_ginfo;
                                curr_ginfo->parent = prev_ginfo;
                        } else { //must jump when if current is for prev neither child nor sibling
                                while (true) {
                                        if (curr_ginfo->depth == prev_ginfo->depth) {
                                                break;
                                        }
                                        prev_ginfo = prev_ginfo->parent;
                                        continue;
                                }
                                /** prev_ginfo is sibling here to follow **/
                                prev_ginfo->next = curr_ginfo;
                                curr_ginfo->prev = curr_ginfo;
                                curr_ginfo->parent = prev_ginfo->parent;
                        }
                        prev_ginfo = curr_ginfo;
                        prev_depth = prev_ginfo->depth;
                }

                error = cgroup_walk_tree_next(0, &tree_handle, &info, lvl);

                if (error && error != ECGEOF) {
                        ret = error;
                        cgroup_walk_tree_end(&tree_handle);
                        goto out_error;
                }
        }

        cgroup_walk_tree_end(&tree_handle);

        //here done for this controller
        //must to return group_info's head of the controller
        return root_ginfo;

out_error:
        free(root_path);
        cgpstree_free_group_tree(root_ginfo);
        return NULL;
}

void
cgpstree_free_controller_list(struct controller_info *head)
{
	struct controller_info *curr;
	struct controller_info *next;

	curr = head;

	while(curr){
		next = curr->next;
		cgpstree_free_group_tree(curr->group_head);
		free(curr);
		curr = next;
	}


}

struct controller_info
*cgpstree_get_controller_list() {
        struct controller_info *cinfo_head = NULL;
        struct controller_info *curr_cinfo = NULL;
        struct controller_info *prev_cinfo = NULL;

        int error = 0;
        void *ctrl_handle;
        int ret = 0;
        char *curr_path = NULL;
        struct cgroup_mount_point info;

        error = cgroup_init();

        if (error) {
                ret = error;
                goto out_error;
        }

        error = cgroup_get_controller_begin(&ctrl_handle, &info);

        if (error && error != ECGEOF) {
                ret = error;
                goto out_error;
        }

        while (error != ECGEOF) {
                if (!curr_path || strcmp(info.path, curr_path) != 0) {
                        if (curr_path)
                                free(curr_path);
                        curr_path=strdup(info.path);
                        if (!curr_path)
                                goto out_errno;

                        // here will be main func to proc
                        curr_cinfo = (struct controller_info*)malloc(
                                             sizeof(struct controller_info));
                        if (cinfo_head == NULL)
                                cinfo_head = curr_cinfo;
                        else
                                prev_cinfo->next = curr_cinfo;

                        curr_cinfo->name = strdup(info.name);
                        curr_cinfo->mount_point = strdup(info.path);
			curr_cinfo->next = NULL;

                        curr_cinfo->group_head = cgpstree_get_group_tree(info);

                        if (curr_cinfo->group_head == NULL)
                                goto out_error;
                }

                error = cgroup_get_controller_next(&ctrl_handle, &info);

                if (error && error != ECGEOF) {
                        ret = error;
                        goto out_error;
                }

                prev_cinfo = curr_cinfo;

        }

out_error:
        if (curr_path)
                free(curr_path);
        cgroup_get_controller_end(&ctrl_handle);
        return cinfo_head;
out_errno:
	cgpstree_free_controller_list(cinfo_head);
        cgroup_get_controller_end(&ctrl_handle);
        return NULL;
}

void
cgpstree_print_space(int lvl)
{
	while(lvl-- > 0)
		printf("\t");
}

void
cgpstree_print_task(struct task_info *tinfo, int lvl)
{
	cgpstree_print_space(lvl);
	printf("%s %d\n",tinfo->proc_name, (int)tinfo->pid);
}

void
cgpstree_print_group(struct group_info *ginfo, int lvl)
{
	char *name = ginfo->name;
	struct task_info *tinfo = ginfo->task_head;

	cgpstree_print_space(lvl);
	printf("- %s\n",name);

	while(tinfo){
		cgpstree_print_task(tinfo, lvl + 1);
		tinfo = tinfo->next;
	}

	if(ginfo->child_head)
		cgpstree_print_group(ginfo->child_head, lvl + 1);

	if(ginfo->next)
		cgpstree_print_group(ginfo->next, lvl);
}


void
cgpstree_print_controller(struct controller_info *cinfo)
{
        char *name = cinfo->name;
	struct group_info *curr;

	curr = cinfo->group_head;
	printf("<%s>\n",name);
	while(curr){
		cgpstree_print_group(curr,0);
		curr = curr->next;
	}
}

void
cgpstree_print_controller_list(struct controller_info *head)
{
        struct controller_info *current;

        current = head;

        while (current) {
                cgpstree_print_controller(current);
                current = current->next;
        }

}

int main(int argc, char * argv[])
{
        struct controller_info *head=NULL;

        head = cgpstree_get_controller_list();

        if (!head) {
                printf("%s failed to get controller tree\n", argv[0]);
                exit(3);
        }

        cgpstree_print_controller_list(head);

        cgpstree_free_controller_list(head);

        return 0;
}
