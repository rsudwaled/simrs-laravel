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
        Schema::create('antrians', function (Blueprint $table) {
            $table->id();
            $table->string('kodebooking')->index()->unique();
            $table->string('jenispasien');
            $table->string('nomorkartu', 13)->nullable();
            $table->string('nik', 16);
            $table->string('nohp');
            $table->string('kodepoli');
            $table->string('namapoli');
            $table->string('pasienbaru');
            $table->string('norm');
            $table->date('tanggalperiksa');
            $table->string('kodedokter');
            $table->string('namadokter');
            $table->string('jampraktek');
            $table->string('jeniskunjungan');
            $table->string('nomorreferensi')->nullable();
            $table->string('nomorantrean');
            $table->string('angkaantrean');
            $table->string('estimasidilayani');
            $table->string('sisakuotajkn');
            $table->string('kuotajkn');
            $table->string('sisakuotanonjkn');
            $table->string('kuotanonjkn');
            $table->text('keterangan');
            // tambahan
            $table->string('nama');
            $table->string('kode_kunjungan')->nullable();
            $table->string('kodetransaksi')->nullable();
            $table->string('lokasi')->nullable();
            $table->string('loket')->nullable();
            $table->string('jenisrujukan')->nullable();
            $table->string('nomorrujukan')->nullable();
            $table->string('nomorsuratkontrol')->nullable();
            $table->string('nomorsep')->nullable();
            $table->string('method')->nullable();
            $table->string('status')->default(0)->nullable();
            $table->string('taskid')->default(0);
            $table->string('user')->nullable();
            $table->string('taskid1')->nullable();
            $table->string('taskid2')->nullable();
            $table->string('taskid3')->nullable();
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
        Schema::dropIfExists('antrians');
    }
};
