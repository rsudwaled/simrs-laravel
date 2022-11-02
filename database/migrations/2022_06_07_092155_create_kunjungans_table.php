<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('kunjungans', function (Blueprint $table) {
            $table->id();
            $table->string('kodekunjungan')->unique();
            $table->string('counter');
            $table->string('norm');
            $table->string('kodeunit');
            $table->string('kodedokter');
            $table->dateTime('tanggal_masuk');
            $table->dateTime('tanggal_keluar');
            $table->string('status');
            $table->string('kodepenjamin');
            $table->string('user');
            $table->string('alasanmasuk');

            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('kunjungans');
    }
};
