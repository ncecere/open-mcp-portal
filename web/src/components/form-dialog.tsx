/* The open-on-mount dialog with a form, a Cancel button and a submit button that most create/edit flows use. */
import { useId, type ReactNode } from "react";
import { Button } from "@/components/ui/button/button";
import { Dialog, DialogClose, type DialogProps } from "@/components/ui/dialog/dialog";
import { Form, type FormProps } from "@/components/ui/field/field";
import { useCloseGuard, useEditTracker } from "./templates/close-guard";

type FormDialogProps = Pick<DialogProps, "title" | "description" | "size"> & {
  onClose: () => void;
  /** Called on submit (the default is prevented). */
  onSubmit: () => void;
  submitLabel: ReactNode;
  /** Shows the submit button as loading. */
  busy?: boolean;
  submitDisabled?: boolean;
  /** Keep a request-bound dialog open until its result is known. */
  closeDisabled?: boolean;
  /** Extra props for the form, e.g. noValidate. */
  formProps?: Omit<FormProps, "id" | "onSubmit" | "children">;
  children: ReactNode;
};

/**
 * A Dialog that is open while mounted (closing calls onClose), wrapping its
 * children in a Form whose submit button sits in the footer next to Cancel.
 * After anything is typed or picked, closing asks "Leave without saving?".
 */
export function FormDialog({ title, description, size, onClose, onSubmit, submitLabel, busy, submitDisabled, closeDisabled, formProps, children }: FormDialogProps) {
  const formId = useId();
  const edits = useEditTracker();
  const guard = useCloseGuard(edits.edited && !busy, onClose);
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && !closeDisabled && guard.requestClose()}
      title={title}
      description={description}
      size={size}
      footer={
        <>
          <DialogClose disabled={closeDisabled}>Cancel</DialogClose>
          <Button type="submit" form={formId} loading={busy} disabled={submitDisabled}>
            {submitLabel}
          </Button>
        </>
      }
    >
      <Form
        {...formProps}
        {...edits.formProps}
        id={formId}
        onSubmit={(e) => {
          e.preventDefault();
          onSubmit();
        }}
      >
        {children}
      </Form>
      {guard.dialog}
    </Dialog>
  );
}
