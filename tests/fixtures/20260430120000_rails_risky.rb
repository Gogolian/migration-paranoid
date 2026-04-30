class AddNotNullToUsersEmail < ActiveRecord::Migration[7.0]
  def change
    change_column_null :users, :email, false
    add_index :orders, :customer_id
    remove_column :products, :legacy_flag
  end
end
